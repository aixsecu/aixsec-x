from auth_lifecycle import AuthLifecycle
import threading


def test_refreshes_once_and_advances_generation():
    runtime=AuthLifecycle('staff'); calls=[]
    def operation():
        calls.append(1)
        return {'expired':len(calls)==1}
    result=runtime.run(operation,lambda value:value['expired'])
    assert result['expired'] is False
    assert runtime.public()['state']=='auth_verified'
    assert runtime.public()['generation']==1
    assert len(calls)==2


def test_unsafe_operation_is_not_replayed():
    runtime=AuthLifecycle('staff'); calls=[]
    result=runtime.run(lambda:(calls.append(1) or {'expired':True}),
                       lambda value:value['expired'],safe_retry=False)
    assert result['expired'] is True
    assert runtime.public()['state']=='auth_expired'
    assert len(calls)==1


def test_failed_refresh_blocks_context():
    runtime=AuthLifecycle('staff'); calls=[]
    runtime.run(lambda:(calls.append(1) or {'expired':True}),lambda value:value['expired'])
    assert runtime.public()['state']=='auth_blocked'
    assert len(calls)==2


def test_concurrent_expiry_refreshes_generation_once():
    runtime=AuthLifecycle('staff')
    barrier=threading.Barrier(4)
    lock=threading.Lock()
    initial=0
    def operation():
        nonlocal initial
        with lock:
            current=initial
            initial += 1
        if current < 4:
            barrier.wait(timeout=5)
            return {'expired':True}
        return {'expired':False}
    results=[]
    threads=[threading.Thread(target=lambda:results.append(
        runtime.run(operation,lambda value:value['expired']))) for _ in range(4)]
    for thread in threads: thread.start()
    for thread in threads: thread.join(timeout=10)
    assert all(not thread.is_alive() for thread in threads)
    assert len(results)==4
    assert all(not result['expired'] for result in results)
    assert runtime.public()['generation']==1
    assert runtime.public()['refreshes']==1
    assert runtime.public()['refresh_ledger']['0']['state']=='complete'


def test_failed_generation_is_not_refreshed_again_and_survives_resume(tmp_path):
    path=tmp_path/'refresh.json'
    runtime=AuthLifecycle('staff').bind(path); calls=[]
    operation=lambda:(calls.append(1) or {'expired':True})
    runtime.run(operation,lambda value:value['expired'])
    assert len(calls)==2
    resumed=AuthLifecycle('staff').bind(path); resumed_calls=[]
    result=resumed.run(lambda:(resumed_calls.append(1) or {'expired':True}),
                       lambda value:value['expired'])
    assert len(resumed_calls)==0
    assert result['data']['coverage']['auth_disposition']=='deferred_auth_expired'
    assert resumed.public()['refreshes']==1
