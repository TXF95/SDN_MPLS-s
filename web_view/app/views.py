from app import app
from flask import render_template
from configure import base_url
import json
import urllib
import urllib2
from collections import defaultdict


@app.route('/')
@app.route('/switch')
def switch():
    switch_url = base_url + '/v1.0/topology/switches'
    switch_json = urllib2.urlopen(urllib2.Request(switch_url)).read()
    switch_dict = json.loads(switch_json)
    return render_template('switch.html', switch_dict=switch_dict)

@app.route('/switch/<dpid>')
def portAndFlow(dpid):
    port_url = base_url + '/v1.0/topology/switches/' + dpid
    port_json = urllib2.urlopen(urllib2.Request(port_url)).read()
    port_dict = (json.loads(port_json))[0]['ports']

    portbw_url = base_url + '/stats/port/' + str(int(dpid,16))
    portbw_json = urllib2.urlopen(urllib2.Request(portbw_url)).read()
    portbw_dict = json.loads(portbw_json)


    flow_url = base_url + '/stats/flow/' +  str(int(dpid,16))
    flow_json = urllib2.urlopen(urllib2.Request(flow_url)).read()
    flow_dict = json.loads(flow_json)
    portAndflow = {'port_dict': port_dict, 'portbw_dict': portbw_dict, 'flow_dict': flow_dict}
    return render_template('portAndFlow.html', portAndflow=portAndflow)


@app.route('/host')
def host():
    host_url = base_url + '/v1.0/topology/hosts'
    host_json = urllib2.urlopen(urllib2.Request(host_url)).read()
    host_dict = json.loads(host_json)
    return render_template('host.html', host_dict=host_dict)

@app.route('/topology')
def topology():
    topology_url = base_url + '/v1.0/topology/links'
    topology_json = urllib2.urlopen(urllib2.Request(topology_url)).read()
    host_url = base_url + '/v1.0/topology/hosts'
    host_json = urllib2.urlopen(urllib2.Request(host_url)).read()
    return render_template('topology.html', topology=topology_json, host=host_json)





