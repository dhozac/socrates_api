import multiprocessing

bind = "127.0.0.1:8000"
workers = multiprocessing.cpu_count() * 2 + 1
max_requests = 1000
max_requests_jitter = 10
loglevel = 'info'
worker_class = 'gevent'
syslog = True
syslog_addr = 'unix:///dev/log#dgram'
graceful_timeout = 40
timeout = 40
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(L)s'
