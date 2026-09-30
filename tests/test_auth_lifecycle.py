from auth_lifecycle import AuthLifecycle


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

