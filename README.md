1. 依赖于tornado的IOLoop, 简单的测试服务
2. 两批用记同时登陆,然后第一批用户向第二批用户发消息, 如下
    '''
    a1->b1
    a2->b2
    a3->b3
    ...
    ```
3. 按时间片工作,如每个时间片为60s, _time_piece为工作时间片,_sleep_loop为sleep时间
    ```
   def __init__(self):
        self._fd_map = {}
        self._start = int(time.time())
        self._io_loop = IOLoop.current()
        self._time_piece = 60  # second
        self._sleep_loop = 5
 
    ```

4. 测试用户数目等的配置文件在config.py
5. 测试账号用users_gen.py生成

