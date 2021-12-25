#!/usr/bin/env python3
import sys
import datetime
import sqlite3
import argparse
import urllib3
import json
import os
import re
import uuid
import logging
import traceback
import redis
from shutil import which
from kubernetes import client, config
from kubernetes.stream import stream

sql_con = sqlite3.connect('example.db');
cur = sql_con.cursor();

aConfiguration = client.Configuration()
aToken = os.environ.get('K8S_TOKEN')
aConfiguration.host = os.environ.get('K8S_URL')
aConfiguration.verify_ssl = False
aConfiguration.api_key = {"authorization": "Bearer " + aToken}
aApiClient = client.ApiClient(aConfiguration)
v1_core = client.CoreV1Api(aApiClient)
v1_apps = client.AppsV1Api(aApiClient)

def_channel = "kubeinvaders_stream"
redis_conn = redis.Redis(unix_socket_path='/tmp/redis.sock')

def print_stdout_and_to_redis(msg):
    log = f"[TRIVY] {msg}"
    print(log)
    redis_conn.publish(def_channel, log)

def resolveOwnerReference(pod) -> dict:
    if pod.metadata.owner_references is None:
        return {
        "kind": "Pod",
        "name": pod.metadata.name,
        "namespace": pod.metadata.namespace,
        "uid": pod.metadata.uid
        }

    else:
        for res in pod.metadata.owner_references:
            if res.kind == 'ReplicaSet':
                replica_set = v1_apps.read_namespaced_replica_set(res.name, pod.metadata.namespace)
                if not replica_set.metadata.owner_references is None:
                    rs_owner_reference = replica_set.metadata.owner_references[0]
                    kind = rs_owner_reference.kind
                    name = rs_owner_reference.name
                    uid = rs_owner_reference.uid
                else:
                    kind = 'ReplicaSet'
                    name = res.name
                    uid = res.uid

            elif res.kind == 'ReplicationController':
                rep_controller = v1_core.read_namespaced_replication_controller(res.name, pod.spec.metadata.namespace)
                if not rep_controller.metadata.owner_references is None:
                    rc_owner_reference = rep_controller.metadata.owner_references[0]
                    kind = rc_owner_reference.kind
                    name = rc_owner_reference.name
                    uid = rc_owner_reference.uid
                else:
                    kind = 'ReplicationController'
                    name = res.name
                    uid = res.uid
            else:
                kind = res.kind
                name = res.name
                uid = res.uid

            return {
                "kind": kind,
                "name": name,
                "namespace": pod.metadata.namespace,
                "uid": uid
            }

def table_exists(name):
    cur.execute(f"SELECT count(name) FROM sqlite_master WHERE type='table' AND name='{name}'")
    if cur.fetchone()[0] == 1:
        return True
    else:
        return False


def check_ns(ns):
    try:
        v1_core.read_namespace(name=ns)
    except Exception as e:
        print_stdout_and_to_redis(f"{e}")
        sys.exit(1)


def store(args):
    if args.namespace:
        check_ns(args.namespace)

    if table_exists('images'):
        print_stdout_and_to_redis("Clean old records of images")
        cur.execute("DROP TABLE images")

    if table_exists('cve'):
        print_stdout_and_to_redis("Clean old records of cve")
        cur.execute("DROP TABLE cve")

    cur.execute('''CREATE TABLE images
        (image text, container text, pod text, owner_name text, owner_kind text, namespace text, date date)''')

    if not table_exists('cve'):
        cur.execute('''CREATE TABLE cve
            (image text, vuln_id text, installed_version text, primary_url text, severity text, date date)''')

    if args.namespace:
        ret = v1_core.list_namespaced_pod(watch=False, namespace=args.namespace)
    else:
        print_stdout_and_to_redis(f"Looking for pods running on all namespaces")
        ret = v1_core.list_pod_for_all_namespaces(watch=False)

    if ret == [] and args.namespace:
        print_stdout_and_to_redis(f"Found 0 runnng pods. Dows namespace {args.namespace} exists?")

    for i in ret.items:
        pod = v1_core.read_namespaced_pod(name=i.metadata.name, namespace=i.metadata.namespace)
        owner = resolveOwnerReference(pod)
        owner_name = owner["name"]
        owner_kind = owner["kind"]
        for container in pod.spec.containers:
            if not already_scanned(container.image):
                scan(container.image)
            date = datetime.datetime.now()
            body = f"Save record for {container.image}"
            print_stdout_and_to_redis(body)
            query = f"""INSERT INTO images VALUES ('{container.image}',
                '{container.name}', 
                '{i.metadata.name}',
                '{owner_name}',
                '{owner_kind}',
                '{i.metadata.namespace}', 
                '{date}')"""
            cur.execute(query)
            sql_con.commit()

    print_stdout_and_to_redis("Images scanning completed")

def get_images(args):
    if not table_exists("images"):
        print_stdout_and_to_redis(f"Please do: ./{sys.argv[0]} store")
        sys.exit(1)
    
    if args.namespace:
        check_ns(args.namespace)
        cur.execute(f"SELECT * FROM images WHERE namespace = '{args.namespace}'")
    else:
        cur.execute(f"SELECT * FROM images")
    
    retval = []
    rows = cur.fetchall()
    if rows == []:
        print_stdout_and_to_redis(f"Query ha returned 0 elements. Please do \"{sys.argv[0]} store\"")
    for row in rows:
        retval.append({
            "image": row[0],
            "container": row[1],
            "pod": row[2],
            "owner": row[3],
            "owen_kind": row[4],
            "namespace": row[5]
        })
        print_stdout_and_to_redis(json.dumps(retval, indent = 4))


def vulns(args):
    cur.execute(f"SELECT * FROM cve")
    stored_cve = cur.fetchall()
    cve_list = {}
    cve_list["cve"] = []

    for cve in stored_cve:
        cur.execute(f"SELECT * FROM images WHERE image = '{cve[0]}'")
        related_images = cur.fetchall()
        oweners = []
        for r_img in related_images:
            tmp_owner = { "owner": r_img[3], "owner_kind": r_img[4], "namespace": r_img[5] }
            if not tmp_owner in oweners:
                oweners.append(tmp_owner)
        cve_dict = {
            "image": cve[0],
            "cve_id": cve[1],
            "installed_version": cve[2],
            "primary_url": cve[3],
            "severity": cve[4],
            "owners": oweners
        }
        cve_list["cve"].append(cve_dict)
    print_stdout_and_to_redis(json.dumps(cve_list, indent = 4))


def already_scanned(img):
    cur.execute(f"SELECT * FROM cve WHERE image = '{img}'")
    rows = cur.fetchall()
    if rows != []:
        print_stdout_and_to_redis(f"Image {img} already checked")
        return True

    cur.execute(f"SELECT * FROM images WHERE image = '{img}'")
    rows = cur.fetchall()
    if rows != []:
        print_stdout_and_to_redis(f"Image {img} already checked")
        return True

    return False


def vuln_dict(vuls_dict_keys, vulns, key):
    if key in vuls_dict_keys:
        return vulns[key]
    return "undefined"


def scan(img):
    id = uuid.uuid1()
    tmp_file = f"/tmp/trivy-{id.node}.json"
    print_stdout_and_to_redis(f'Scan {img}')
    stream = os.popen(f'trivy -f json -o {tmp_file} {img}')
    stream.read()

    with open(tmp_file) as json_file:
        data = json.load(json_file)

    if "Results" in data:
        data = data["Results"]

    for results in data:
        if "Vulnerabilities" in results:
            for vulns in results["Vulnerabilities"]:
                vulnid = vuln_dict(vulns.keys(), vulns, "VulnerabilityID")
                inst_ver = vuln_dict(vulns.keys(), vulns, "InstalledVersion")
                prim_url = vuln_dict(vulns.keys(), vulns, "PrimaryURL")
                severity = vuln_dict(vulns.keys(), vulns, "Severity")
                if severity in ["HIGH", "CRITICAL"]:
                    date = datetime.datetime.now()
                    query = f"SELECT * FROM cve WHERE vuln_id = '{vulnid}'"
                    cur.execute(query)
                    rows = cur.fetchall()
                    if rows == []:
                        query = f"INSERT INTO cve VALUES ('{img}', '{vulnid}', '{inst_ver}', '{prim_url}', '{severity}', '{date}')"
                        cur.execute(query)
                        sql_con.commit()
                    else:
                        print_stdout_and_to_redis(f"{vulnid} already found during this scanning session")

def tool_exists(name):
    return which(name) is not None

if __name__ == '__main__':
    if not tool_exists("trivy"):
        print_stdout_and_to_redis("trivy is not installed on this system, please install it")
        sys.exit(1)

    urllib3.disable_warnings()
    parser = argparse.ArgumentParser(prog='secpod_wrap')

    sub_parsers = parser.add_subparsers(help='sub-command help')

    parser_store = sub_parsers.add_parser('store', help='Save pod and images in SQLite')
    parser_store.set_defaults(func=store)
    parser_store.add_argument('--namespace', type=str, help='Get images of a specific namespace', dest='namespace')
    parser_store.add_argument('--all-namespaces', type=bool, help='Get images of all namespaces', dest='all_namespaces')

    parser_images = sub_parsers.add_parser('images', help='Get images list')
    parser_images.set_defaults(func=get_images)
    parser_images.add_argument('--namespace', type=str, help='Get images of a specific namespace', dest='namespace')
    parser_images.add_argument('--pod', type=str, help='Name of the pod', dest='pod')

    parser_podvulns = sub_parsers.add_parser('vulns', help='Get images cve of a specific pod')
    parser_podvulns.set_defaults(func=vulns)
    parser_podvulns.add_argument('--pod', type=str, help='Name of the pod', dest='pod')

    args = parser.parse_args()

    if len(sys.argv) < 2:
        parser.print_usage()
        sys.exit(1)
    args.func(args)