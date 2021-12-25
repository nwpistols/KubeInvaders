import tornado.httpserver
import tornado.websocket
import tornado.ioloop
import tornado.web
import redis
import requests
import json
import os
import urllib.parse
import urllib3
import hashlib
from dateutil import parser

f = open("/var/run/secrets/kubernetes.io/serviceaccount/token", "r")
token = f.read()
kube_host = f"https://{os.environ.get('KUBERNETES_SERVICE_HOST')}:{os.environ.get('KUBERNETES_PORT_443_TCP_PORT')}"
headers = {"Content-Type": "application/json;", "Authorization": "Bearer " + token}
urllib3.disable_warnings()

redis_conn = redis.Redis(unix_socket_path='/tmp/redis.sock')
pubsub = redis_conn.pubsub()
pubsub.subscribe("kubeinvaders_stream")

class MyWebSocketServer(tornado.websocket.WebSocketHandler):
    def open(self):
        print('Established new connection')
    def on_message(self, message):
        print('Received message: %s' % message)
        #self.write_message("[KUBEINV_INFO] Received websocket message")
        message_json = json.loads(message)
        namespace = message_json["namespace"]
        if message_json["action"] == "GETEVENTS":
            endpoint = urllib.parse.urljoin(kube_host, f"/api/v1/namespaces/{namespace}/events")
            print(f"Endpoint for getting events: {endpoint}")
            response = requests.get(endpoint, headers=headers, verify=False)
            event_list = json.loads(response.content)
            print(f"Taking target namespace from {message}")
            for event in event_list["items"]:
                print('Checking if eventResourceVersion exists in Redis...')
                if redis_conn.get('eventResourceVersion'):
                    redis_resource_ver = int(redis_conn.get('eventResourceVersion'))
                else:
                    redis_resource_ver = 0
                resource_ver = int(event['metadata']['resourceVersion'])
                umarell_msg = {}
                umarell_msg['namespace'] = event['metadata']['namespace']
                umarell_msg['creationTimestamp'] = event['metadata']['creationTimestamp']
                umarell_msg['involvedObject'] = event['involvedObject']['kind']
                umarell_msg['reason'] = event['reason']
                umarell_msg['message'] = event['message']
                if redis_resource_ver:
                    print(f"Current eventResourceVersion in Redis is {redis_resource_ver}")
                    print(f"Current resourceVersion of the event is {resource_ver}")
                    if resource_ver > redis_resource_ver:
                        print("[EVENTS]Current ResourceVersion is greater then ResourceVersion in Redis")
                        redis_conn.set('eventResourceVersion', resource_ver)
                        self.write_message(umarell_msg)
                    else:
                        print("Event has been already sent to KubeInvaders!")
                else:
                    print('eventResourceVersion is not present in Redis...')
                    redis_conn.set('eventResourceVersion', resource_ver)
                    print('Sending message of event to KubeInvaders...')
                    self.write_message(umarell_msg)
        elif message_json["action"] == "GETPODLODS":
            endpoint = urllib.parse.urljoin(kube_host, f"/api/v1/namespaces/{namespace}/pods")
            print(f"Endpoint for getting pods: {endpoint}")
            response = requests.get(endpoint, headers=headers, verify=False)
            pods_list = json.loads(response.content)
            for pod in pods_list['items']:
                pod_name = pod['metadata']['name']
                print(f"Looking for logs of the pod {pod_name}")
                for container in pod['spec']['containers']:
                    print(f"Found container {container['name']} in {pod_name}")
                    endpoint = urllib.parse.urljoin(kube_host, f"/api/v1/namespaces/{namespace}/pods/{pod_name}/log?container={container['name']}&sinceSeconds=5&timestamps=true")
                    response = requests.get(endpoint, headers=headers, verify=False)
                    cntlog = response.content.decode("utf-8")
                    if len(cntlog) > 0:
                        print(f"Response of podlogs: {cntlog}")
                        print('Checking if eventResourceVersion exists in Redis...')
                        hash_object = hashlib.sha256(cntlog)
                        hex_dig = hash_object.hexdigest()
                        if redis_conn.get(hex_dig):
                            print(f"The log with hash {hex_dig} is already present in Redis. This log will not be sent to KubeInvaders")
                        else:
                            print(f"The log with hash {hex_dig} is not already present in Redis. This log will be sent to KubeInvaders")
                            redis_conn.set(hex_dig, 1)
                            redis_conn.expire(hex_dig, 30)
                            umarell_msg = {}
                            umarell_msg['namespace'] = namespace
                            split = cntlog.split(' ')
                            timestamp = split[0]
                            split.remove(timestamp)
                            umarell_msg['timestamp'] = timestamp
                            umarell_msg['message'] = ' '.join(split)
                            print(f"Sending this log to KubeInvaders: {umarell_msg}")
                            self.write_message(umarell_msg)
    def on_close(self):
        print('Connection closed')
    def check_origin(self, origin):
        return True

application = tornado.web.Application([
    (r'/websocket', MyWebSocketServer),
])

if __name__ == "__main__":
    http_server = tornado.httpserver.HTTPServer(application)
    http_server.listen(8765)
    tornado.ioloop.IOLoop.instance().start()