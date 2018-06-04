//
//  arbor.js - version 0.91
//  a graph vizualization toolkit
//
//  Copyright (c) 2011 Samizdat Drafting Co.
//  Physics code derived from springy.js, copyright (c) 2010 Dennis Hotson
// 
//  Permission is hereby granted, free of charge, to any person
//  obtaining a copy of this software and associated documentation
//  files (the "Software"), to deal in the Software without
//  restriction, including without limitation the rights to use,
//  copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the
//  Software is furnished to do so, subject to the following
//  conditions:
// 
//  The above copyright notice and this permission notice shall be
//  included in all copies or substantial portions of the Software.
// 
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
//  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
//  OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
//  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
//  HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
//  WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
//  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
//  OTHER DEALINGS IN THE SOFTWARE.
//

(function ($) {

    /*        etc.js */
    var trace = function (msg) {
        if (typeof(window) == "undefined" || !window.console) {
            return
        }
        var len = arguments.length;
        var args = [];
        for (var i = 0; i < len; i++) {
            args.push("arguments[" + i + "]")
        }
        eval("console.log(" + args.join(",") + ")")
    };
    var dirname = function (a) {
        var b = a.replace(/^\/?(.*?)\/?$/, "$1").split("/");
        b.pop();
        return "/" + b.join("/")
    };
    var basename = function (b) {
        var c = b.replace(/^\/?(.*?)\/?$/, "$1").split("/");
        var a = c.pop();
        if (a == "") {
            return null
        } else {
            return a
        }
    };
    var _ordinalize_re = /(\d)(?=(\d\d\d)+(?!\d))/g;
    var ordinalize = function (a) {
        var b = "" + a;
        if (a < 11000) {
            b = ("" + a).replace(_ordinalize_re, "$1,")
        } else {
            if (a < 1000000) {
                b = Math.floor(a / 1000) + "k"
            } else {
                if (a < 1000000000) {
                    b = ("" + Math.floor(a / 1000)).replace(_ordinalize_re, "$1,") + "m"
                }
            }
        }
        return b
    };
    var nano = function (a, b) {
        return a.replace(/\{([\w\-\.]*)}/g, function (f, c) {
            var d = c.split("."), e = b[d.shift()];
            $.each(d, function () {
                if (e.hasOwnProperty(this)) {
                    e = e[this]
                } else {
                    e = f
                }
            });
            return e
        })
    };
    var objcopy = function (a) {
        if (a === undefined) {
            return undefined
        }
        if (a === null) {
            return null
        }
        if (a.parentNode) {
            return a
        }
        switch (typeof a) {
            case"string":
                return a.substring(0);
                break;
            case"number":
                return a + 0;
                break;
            case"boolean":
                return a === true;
                break
        }
        var b = ($.isArray(a)) ? [] : {};
        $.each(a, function (d, c) {
            b[d] = objcopy(c)
        });
        return b
    };
    var objmerge = function (d, b) {
        d = d || {};
        b = b || {};
        var c = objcopy(d);
        for (var a in b) {
            c[a] = b[a]
        }
        return c
    };
    var objcmp = function (e, c, d) {
        if (!e || !c) {
            return e === c
        }
        if (typeof e != typeof c) {
            return false
        }
        if (typeof e != "object") {
            return e === c
        } else {
            if ($.isArray(e)) {
                if (!($.isArray(c))) {
                    return false
                }
                if (e.length != c.length) {
                    return false
                }
            } else {
                var h = [];
                for (var f in e) {
                    if (e.hasOwnProperty(f)) {
                        h.push(f)
                    }
                }
                var g = [];
                for (var f in c) {
                    if (c.hasOwnProperty(f)) {
                        g.push(f)
                    }
                }
                if (!d) {
                    h.sort();
                    g.sort()
                }
                if (h.join(",") !== g.join(",")) {
                    return false
                }
            }
            var i = true;
            $.each(e, function (a) {
                var b = objcmp(e[a], c[a]);
                i = i && b;
                if (!i) {
                    return false
                }
            });
            return i
        }
    };
    var objkeys = function (b) {
        var a = [];
        $.each(b, function (d, c) {
            if (b.hasOwnProperty(d)) {
                a.push(d)
            }
        });
        return a
    };
    var objcontains = function (c) {
        if (!c || typeof c != "object") {
            return false
        }
        for (var b = 1, a = arguments.length; b < a; b++) {
            if (c.hasOwnProperty(arguments[b])) {
                return true
            }
        }
        return false
    };
    var uniq = function (b) {
        var a = b.length;
        var d = {};
        for (var c = 0; c < a; c++) {
            d[b[c]] = true
        }
        return objkeys(d)
    };
    var arbor_path = function () {
        var a = $("script").map(function (b) {
            var c = $(this).attr("src");
            if (!c) {
                return
            }
            if (c.match(/arbor[^\/\.]*.js|dev.js/)) {
                return c.match(/.*\//) || "/"
            }
        });
        if (a.length > 0) {
            return a[0]
        } else {
            return null
        }
    };
    /*     kernel.js */
    var Kernel = function (b) {
        var k = window.location.protocol == "file:" && navigator.userAgent.toLowerCase().indexOf("chrome") > -1;
        var a = (window.Worker !== undefined && !k);
        var i = null;
        var c = null;
        var f = [];
        f.last = new Date();
        var l = null;
        var e = null;
        var d = null;
        var h = null;
        var g = false;
        var j = {
            system: b, tween: null, nodes: {}, init: function () {
                if (typeof(Tween) != "undefined") {
                    c = Tween()
                } else {
                    if (typeof(arbor.Tween) != "undefined") {
                        c = arbor.Tween()
                    } else {
                        c = {
                            busy: function () {
                                return false
                            }, tick: function () {
                                return true
                            }, to: function () {
                                trace("Please include arbor-tween.js to enable tweens");
                                c.to = function () {
                                };
                                return
                            }
                        }
                    }
                }
                j.tween = c;
                var m = b.parameters();
                if (a) {
                    trace("using web workers");
                    l = setInterval(j.screenUpdate, m.timeout);
                    i = new Worker(arbor_path() + "arbor.js");
                    i.onmessage = j.workerMsg;
                    i.onerror = function (n) {
                        trace("physics:", n)
                    };
                    i.postMessage({type: "physics", physics: objmerge(m, {timeout: Math.ceil(m.timeout)})})
                } else {
                    trace("couldn't use web workers, be careful...");
                    i = Physics(m.dt, m.stiffness, m.repulsion, m.friction, j.system._updateGeometry);
                    j.start()
                }
                return j
            }, graphChanged: function (m) {
                if (a) {
                    i.postMessage({type: "changes", changes: m})
                } else {
                    i._update(m)
                }
                j.start()
            }, particleModified: function (n, m) {
                if (a) {
                    i.postMessage({type: "modify", id: n, mods: m})
                } else {
                    i.modifyNode(n, m)
                }
                j.start()
            }, physicsModified: function (m) {
                if (!isNaN(m.timeout)) {
                    if (a) {
                        clearInterval(l);
                        l = setInterval(j.screenUpdate, m.timeout)
                    } else {
                        clearInterval(d);
                        d = null
                    }
                }
                if (a) {
                    i.postMessage({type: "sys", param: m})
                } else {
                    i.modifyPhysics(m)
                }
                j.start()
            }, workerMsg: function (n) {
                var m = n.data.type;
                if (m == "geometry") {
                    j.workerUpdate(n.data)
                } else {
                    trace("physics:", n.data)
                }
            }, _lastPositions: null, workerUpdate: function (m) {
                j._lastPositions = m;
                j._lastBounds = m.bounds
            }, _lastFrametime: new Date().valueOf(), _lastBounds: null, _currentRenderer: null, screenUpdate: function () {
                var n = new Date().valueOf();
                var m = false;
                if (j._lastPositions !== null) {
                    j.system._updateGeometry(j._lastPositions);
                    j._lastPositions = null;
                    m = true
                }
                if (c && c.busy()) {
                    m = true
                }
                if (j.system._updateBounds(j._lastBounds)) {
                    m = true
                }
                if (m) {
                    var o = j.system.renderer;
                    if (o !== undefined) {
                        if (o !== e) {
                            o.init(j.system);
                            e = o
                        }
                        if (c) {
                            c.tick()
                        }
                        o.redraw();
                        var p = f.last;
                        f.last = new Date();
                        f.push(f.last - p);
                        if (f.length > 50) {
                            f.shift()
                        }
                    }
                }
            }, physicsUpdate: function () {
                if (c) {
                    c.tick()
                }
                i.tick();
                var n = j.system._updateBounds();
                if (c && c.busy()) {
                    n = true
                }
                var o = j.system.renderer;
                var m = new Date();
                var o = j.system.renderer;
                if (o !== undefined) {
                    if (o !== e) {
                        o.init(j.system);
                        e = o
                    }
                    o.redraw({timestamp: m})
                }
                var q = f.last;
                f.last = m;
                f.push(f.last - q);
                if (f.length > 50) {
                    f.shift()
                }
                var p = i.systemEnergy();
                if ((p.mean + p.max) / 2 < 0.05) {
                    if (h === null) {
                        h = new Date().valueOf()
                    }
                    if (new Date().valueOf() - h > 1000) {
                        clearInterval(d);
                        d = null
                    } else {
                    }
                } else {
                    h = null
                }
            }, fps: function (n) {
                if (n !== undefined) {
                    var q = 1000 / Math.max(1, targetFps);
                    j.physicsModified({timeout: q})
                }
                var r = 0;
                for (var p = 0, o = f.length; p < o; p++) {
                    r += f[p]
                }
                var m = r / Math.max(1, f.length);
                if (!isNaN(m)) {
                    return Math.round(1000 / m)
                } else {
                    return 0
                }
            }, start: function (m) {
                if (d !== null) {
                    return
                }
                if (g && !m) {
                    return
                }
                g = false;
                if (a) {
                    i.postMessage({type: "start"})
                } else {
                    h = null;
                    d = setInterval(j.physicsUpdate, j.system.parameters().timeout)
                }
            }, stop: function () {
                g = true;
                if (a) {
                    i.postMessage({type: "stop"})
                } else {
                    if (d !== null) {
                        clearInterval(d);
                        d = null
                    }
                }
            }
        };
        return j.init()
    };
    /*      atoms.js */
    var Node = function (a) {
        this._id = _nextNodeId++;
        this.data = a || {};
        this._mass = (a.mass !== undefined) ? a.mass : 1;
        this._fixed = (a.fixed === true) ? true : false;
        this._p = new Point((typeof(a.x) == "number") ? a.x : null, (typeof(a.y) == "number") ? a.y : null);
        delete this.data.x;
        delete this.data.y;
        delete this.data.mass;
        delete this.data.fixed
    };
    var _nextNodeId = 1;
    var Edge = function (b, c, a) {
        this._id = _nextEdgeId--;
        this.source = b;
        this.target = c;
        this.length = (a.length !== undefined) ? a.length : 1;
        this.data = (a !== undefined) ? a : {};
        delete this.data.length
    };
    var _nextEdgeId = -1;
    var Particle = function (a, b) {
        this.p = a;
        this.m = b;
        this.v = new Point(0, 0);
        this.f = new Point(0, 0)
    };
    Particle.prototype.applyForce = function (a) {
        this.f = this.f.add(a.divide(this.m))
    };
    var Spring = function (c, b, d, a) {
        this.point1 = c;
        this.point2 = b;
        this.length = d;
        this.k = a
    };
    Spring.prototype.distanceToParticle = function (a) {
        var c = that.point2.p.subtract(that.point1.p).normalize().normal();
        var b = a.p.subtract(that.point1.p);
        return Math.abs(b.x * c.x + b.y * c.y)
    };
    var Point = function (a, b) {
        if (a && a.hasOwnProperty("y")) {
            b = a.y;
            a = a.x
        }
        this.x = a;
        this.y = b
    };
    Point.random = function (a) {
        a = (a !== undefined) ? a : 5;
        return new Point(2 * a * (Math.random() - 0.5), 2 * a * (Math.random() - 0.5))
    };
    Point.prototype = {
        exploded: function () {
            return (isNaN(this.x) || isNaN(this.y))
        }, add: function (a) {
            return new Point(this.x + a.x, this.y + a.y)
        }, subtract: function (a) {
            return new Point(this.x - a.x, this.y - a.y)
        }, multiply: function (a) {
            return new Point(this.x * a, this.y * a)
        }, divide: function (a) {
            return new Point(this.x / a, this.y / a)
        }, magnitude: function () {
            return Math.sqrt(this.x * this.x + this.y * this.y)
        }, normal: function () {
            return new Point(-this.y, this.x)
        }, normalize: function () {
            return this.divide(this.magnitude())
        }
    };
    /*     system.js */
    var ParticleSystem = function (d, p, e, f, t, l, q) {
        var j = [];
        var h = null;
        var k = 0;
        var u = null;
        var m = 0.04;
        var i = [20, 20, 20, 20];
        var n = null;
        var o = null;
        if (typeof p == "object") {
            var s = p;
            e = s.friction;
            d = s.repulsion;
            t = s.fps;
            l = s.dt;
            p = s.stiffness;
            f = s.gravity;
            q = s.precision
        }
        e = isNaN(e) ? 0.5 : e;
        d = isNaN(d) ? 1000 : d;
        t = isNaN(t) ? 55 : t;
        p = isNaN(p) ? 600 : p;
        l = isNaN(l) ? 0.02 : l;
        q = isNaN(q) ? 0.6 : q;
        f = (f === true);
        var r = (t !== undefined) ? 1000 / t : 1000 / 50;
        var b = {repulsion: d, stiffness: p, friction: e, dt: l, gravity: f, precision: q, timeout: r};
        var a;
        var c = {renderer: null, tween: null, nodes: {}, edges: {}, adjacency: {}, names: {}, kernel: null};
        var g = {
            parameters: function (v) {
                if (v !== undefined) {
                    if (!isNaN(v.precision)) {
                        v.precision = Math.max(0, Math.min(1, v.precision))
                    }
                    $.each(b, function (x, w) {
                        if (v[x] !== undefined) {
                            b[x] = v[x]
                        }
                    });
                    c.kernel.physicsModified(v)
                }
                return b
            }, fps: function (v) {
                if (v === undefined) {
                    return c.kernel.fps()
                } else {
                    g.parameters({timeout: 1000 / (v || 50)})
                }
            }, start: function () {
                c.kernel.start()
            }, stop: function () {
                c.kernel.stop()
            }, addNode: function (w, B) {
                B = B || {};
                var C = c.names[w];
                if (C) {
                    C.data = B;
                    return C
                } else {
                    if (w != undefined) {
                        var v = (B.x != undefined) ? B.x : null;
                        var D = (B.y != undefined) ? B.y : null;
                        var A = (B.fixed) ? 1 : 0;
                        var z = new Node(B);
                        z.name = w;
                        c.names[w] = z;
                        c.nodes[z._id] = z;
                        j.push({t: "addNode", id: z._id, m: z.mass, x: v, y: D, f: A});
                        g._notify();
                        return z
                    }
                }
            }, pruneNode: function (w) {
                var v = g.getNode(w);
                if (typeof(c.nodes[v._id]) !== "undefined") {
                    delete c.nodes[v._id];
                    delete c.names[v.name]
                }
                $.each(c.edges, function (y, x) {
                    if (x.source._id === v._id || x.target._id === v._id) {
                        g.pruneEdge(x)
                    }
                });
                j.push({t: "dropNode", id: v._id});
                g._notify()
            }, getNode: function (v) {
                if (v._id !== undefined) {
                    return v
                } else {
                    if (typeof v == "string" || typeof v == "number") {
                        return c.names[v]
                    }
                }
            }, eachNode: function (v) {
                $.each(c.nodes, function (y, x) {
                    if (x._p.x == null || x._p.y == null) {
                        return
                    }
                    var w = (u !== null) ? g.toScreen(x._p) : x._p;
                    v.call(g, x, w)
                })
            }, addEdge: function (z, A, y) {
                z = g.getNode(z) || g.addNode(z);
                A = g.getNode(A) || g.addNode(A);
                y = y || {};
                var x = new Edge(z, A, y);
                var B = z._id;
                var C = A._id;
                c.adjacency[B] = c.adjacency[B] || {};
                c.adjacency[B][C] = c.adjacency[B][C] || [];
                var w = (c.adjacency[B][C].length > 0);
                if (w) {
                    $.extend(c.adjacency[B][C].data, x.data);
                    return
                } else {
                    c.edges[x._id] = x;
                    c.adjacency[B][C].push(x);
                    var v = (x.length !== undefined) ? x.length : 1;
                    j.push({t: "addSpring", id: x._id, fm: B, to: C, l: v});
                    g._notify()
                }
                return x
            }, pruneEdge: function (A) {
                j.push({t: "dropSpring", id: A._id});
                delete c.edges[A._id];
                for (var v in c.adjacency) {
                    for (var B in c.adjacency[v]) {
                        var w = c.adjacency[v][B];
                        for (var z = w.length - 1; z >= 0; z--) {
                            if (c.adjacency[v][B][z]._id === A._id) {
                                c.adjacency[v][B].splice(z, 1)
                            }
                        }
                    }
                }
                g._notify()
            }, getEdges: function (w, v) {
                w = g.getNode(w);
                v = g.getNode(v);
                if (!w || !v) {
                    return []
                }
                if (typeof(c.adjacency[w._id]) !== "undefined" && typeof(c.adjacency[w._id][v._id]) !== "undefined") {
                    return c.adjacency[w._id][v._id]
                }
                return []
            }, getEdgesFrom: function (v) {
                v = g.getNode(v);
                if (!v) {
                    return []
                }
                if (typeof(c.adjacency[v._id]) !== "undefined") {
                    var w = [];
                    $.each(c.adjacency[v._id], function (y, x) {
                        w = w.concat(x)
                    });
                    return w
                }
                return []
            }, getEdgesTo: function (v) {
                v = g.getNode(v);
                if (!v) {
                    return []
                }
                var w = [];
                $.each(c.edges, function (y, x) {
                    if (x.target == v) {
                        w.push(x)
                    }
                });
                return w
            }, eachEdge: function (v) {
                $.each(c.edges, function (z, x) {
                    var y = c.nodes[x.source._id]._p;
                    var w = c.nodes[x.target._id]._p;
                    if (y.x == null || w.x == null) {
                        return
                    }
                    y = (u !== null) ? g.toScreen(y) : y;
                    w = (u !== null) ? g.toScreen(w) : w;
                    if (y && w) {
                        v.call(g, x, y, w)
                    }
                })
            }, prune: function (w) {
                var v = {dropped: {nodes: [], edges: []}};
                if (w === undefined) {
                    $.each(c.nodes, function (y, x) {
                        v.dropped.nodes.push(x);
                        g.pruneNode(x)
                    })
                } else {
                    g.eachNode(function (y) {
                        var x = w.call(g, y, {from: g.getEdgesFrom(y), to: g.getEdgesTo(y)});
                        if (x) {
                            v.dropped.nodes.push(y);
                            g.pruneNode(y)
                        }
                    })
                }
                return v
            }, graft: function (w) {
                var v = {added: {nodes: [], edges: []}};
                if (w.nodes) {
                    $.each(w.nodes, function (y, x) {
                        var z = g.getNode(y);
                        if (z) {
                            z.data = x
                        } else {
                            v.added.nodes.push(g.addNode(y, x))
                        }
                        c.kernel.start()
                    })
                }
                if (w.edges) {
                    $.each(w.edges, function (z, x) {
                        var y = g.getNode(z);
                        if (!y) {
                            v.added.nodes.push(g.addNode(z, {}))
                        }
                        $.each(x, function (D, A) {
                            var C = g.getNode(D);
                            if (!C) {
                                v.added.nodes.push(g.addNode(D, {}))
                            }
                            var B = g.getEdges(z, D);
                            if (B.length > 0) {
                                B[0].data = A
                            } else {
                                v.added.edges.push(g.addEdge(z, D, A))
                            }
                        })
                    })
                }
                return v
            }, merge: function (w) {
                var v = {added: {nodes: [], edges: []}, dropped: {nodes: [], edges: []}};
                $.each(c.edges, function (A, z) {
                    if ((w.edges[z.source.name] === undefined || w.edges[z.source.name][z.target.name] === undefined)) {
                        g.pruneEdge(z);
                        v.dropped.edges.push(z)
                    }
                });
                var y = g.prune(function (A, z) {
                    if (w.nodes[A.name] === undefined) {
                        v.dropped.nodes.push(A);
                        return true
                    }
                });
                var x = g.graft(w);
                v.added.nodes = v.added.nodes.concat(x.added.nodes);
                v.added.edges = v.added.edges.concat(x.added.edges);
                v.dropped.nodes = v.dropped.nodes.concat(y.dropped.nodes);
                v.dropped.edges = v.dropped.edges.concat(y.dropped.edges);
                return v
            }, tweenNode: function (y, v, x) {
                var w = g.getNode(y);
                if (w) {
                    c.tween.to(w, v, x)
                }
            }, tweenEdge: function (w, v, z, y) {
                if (y === undefined) {
                    g._tweenEdge(w, v, z)
                } else {
                    var x = g.getEdges(w, v);
                    $.each(x, function (A, B) {
                        g._tweenEdge(B, z, y)
                    })
                }
            }, _tweenEdge: function (w, v, x) {
                if (w && w._id !== undefined) {
                    c.tween.to(w, v, x)
                }
            }, _updateGeometry: function (y) {
                if (y != undefined) {
                    var v = (y.epoch < k);
                    a = y.energy;
                    var z = y.geometry;
                    if (z !== undefined) {
                        for (var x = 0, w = z.length / 3; x < w; x++) {
                            var A = z[3 * x];
                            if (v && c.nodes[A] == undefined) {
                                continue
                            }
                            c.nodes[A]._p.x = z[3 * x + 1];
                            c.nodes[A]._p.y = z[3 * x + 2]
                        }
                    }
                }
            }, screen: function (v) {
                if (v == undefined) {
                    return {size: (u) ? objcopy(u) : undefined, padding: i.concat(), step: m}
                }
                if (v.size !== undefined) {
                    g.screenSize(v.size.width, v.size.height)
                }
                if (!isNaN(v.step)) {
                    g.screenStep(v.step)
                }
                if (v.padding !== undefined) {
                    g.screenPadding(v.padding)
                }
            }, screenSize: function (v, w) {
                u = {width: v, height: w};
                g._updateBounds()
            }, screenPadding: function (y, z, v, w) {
                if ($.isArray(y)) {
                    trbl = y
                } else {
                    trbl = [y, z, v, w]
                }
                var A = trbl[0];
                var x = trbl[1];
                var B = trbl[2];
                if (x === undefined) {
                    trbl = [A, A, A, A]
                } else {
                    if (B == undefined) {
                        trbl = [A, x, A, x]
                    }
                }
                i = trbl
            }, screenStep: function (v) {
                m = v
            }, toScreen: function (x) {
                if (!n || !u) {
                    return
                }
                var w = i || [0, 0, 0, 0];
                var v = n.bottomright.subtract(n.topleft);
                var z = w[3] + x.subtract(n.topleft).divide(v.x).x * (u.width - (w[1] + w[3]));
                var y = w[0] + x.subtract(n.topleft).divide(v.y).y * (u.height - (w[0] + w[2]));
                return arbor.Point(z, y)
            }, fromScreen: function (z) {
                if (!n || !u) {
                    return
                }
                var y = i || [0, 0, 0, 0];
                var x = n.bottomright.subtract(n.topleft);
                var w = (z.x - y[3]) / (u.width - (y[1] + y[3])) * x.x + n.topleft.x;
                var v = (z.y - y[0]) / (u.height - (y[0] + y[2])) * x.y + n.topleft.y;
                return arbor.Point(w, v)
            }, _updateBounds: function (w) {
                if (u === null) {
                    return
                }
                if (w) {
                    o = w
                } else {
                    o = g.bounds()
                }
                var z = new Point(o.bottomright.x, o.bottomright.y);
                var y = new Point(o.topleft.x, o.topleft.y);
                var B = z.subtract(y);
                var v = y.add(B.divide(2));
                var x = 4;
                var D = new Point(Math.max(B.x, x), Math.max(B.y, x));
                o.topleft = v.subtract(D.divide(2));
                o.bottomright = v.add(D.divide(2));
                if (!n) {
                    if ($.isEmptyObject(c.nodes)) {
                        return false
                    }
                    n = o;
                    return true
                }
                var C = m;
                _newBounds = {
                    bottomright: n.bottomright.add(o.bottomright.subtract(n.bottomright).multiply(C)),
                    topleft: n.topleft.add(o.topleft.subtract(n.topleft).multiply(C))
                };
                var A = new Point(n.topleft.subtract(_newBounds.topleft).magnitude(), n.bottomright.subtract(_newBounds.bottomright).magnitude());
                if (A.x * u.width > 1 || A.y * u.height > 1) {
                    n = _newBounds;
                    return true
                } else {
                    return false
                }
            }, energy: function () {
                return a
            }, bounds: function () {
                var w = null;
                var v = null;
                $.each(c.nodes, function (z, y) {
                    if (!w) {
                        w = new Point(y._p);
                        v = new Point(y._p);
                        return
                    }
                    var x = y._p;
                    if (x.x === null || x.y === null) {
                        return
                    }
                    if (x.x > w.x) {
                        w.x = x.x
                    }
                    if (x.y > w.y) {
                        w.y = x.y
                    }
                    if (x.x < v.x) {
                        v.x = x.x
                    }
                    if (x.y < v.y) {
                        v.y = x.y
                    }
                });
                if (w && v) {
                    return {bottomright: w, topleft: v}
                } else {
                    return {topleft: new Point(-1, -1), bottomright: new Point(1, 1)}
                }
            }, nearest: function (x) {
                if (u !== null) {
                    x = g.fromScreen(x)
                }
                var w = {node: null, point: null, distance: null};
                var v = g;
                $.each(c.nodes, function (B, y) {
                    var z = y._p;
                    if (z.x === null || z.y === null) {
                        return
                    }
                    var A = z.subtract(x).magnitude();
                    if (w.distance === null || A < w.distance) {
                        w = {node: y, point: z, distance: A};
                        if (u !== null) {
                            w.screenPoint = g.toScreen(z)
                        }
                    }
                });
                if (w.node) {
                    if (u !== null) {
                        w.distance = g.toScreen(w.node.p).subtract(g.toScreen(x)).magnitude()
                    }
                    return w
                } else {
                    return null
                }
            }, _notify: function () {
                if (h === null) {
                    k++
                } else {
                    clearTimeout(h)
                }
                h = setTimeout(g._synchronize, 20)
            }, _synchronize: function () {
                if (j.length > 0) {
                    c.kernel.graphChanged(j);
                    j = [];
                    h = null
                }
            }
        };
        c.kernel = Kernel(g);
        c.tween = c.kernel.tween || null;
        Node.prototype.__defineGetter__("p", function () {
            var w = this;
            var v = {};
            v.__defineGetter__("x", function () {
                return w._p.x
            });
            v.__defineSetter__("x", function (x) {
                c.kernel.particleModified(w._id, {x: x})
            });
            v.__defineGetter__("y", function () {
                return w._p.y
            });
            v.__defineSetter__("y", function (x) {
                c.kernel.particleModified(w._id, {y: x})
            });
            v.__proto__ = Point.prototype;
            return v
        });
        Node.prototype.__defineSetter__("p", function (v) {
            this._p.x = v.x;
            this._p.y = v.y;
            c.kernel.particleModified(this._id, {x: v.x, y: v.y})
        });
        Node.prototype.__defineGetter__("mass", function () {
            return this._mass
        });
        Node.prototype.__defineSetter__("mass", function (v) {
            this._mass = v;
            c.kernel.particleModified(this._id, {m: v})
        });
        Node.prototype.__defineSetter__("tempMass", function (v) {
            c.kernel.particleModified(this._id, {_m: v})
        });
        Node.prototype.__defineGetter__("fixed", function () {
            return this._fixed
        });
        Node.prototype.__defineSetter__("fixed", function (v) {
            this._fixed = v;
            c.kernel.particleModified(this._id, {f: v ? 1 : 0})
        });
        return g
    };
    /* barnes-hut.js */
    var BarnesHutTree = function () {
        var b = [];
        var a = 0;
        var e = null;
        var d = 0.5;
        var c = {
            init: function (g, h, f) {
                d = f;
                a = 0;
                e = c._newBranch();
                e.origin = g;
                e.size = h.subtract(g)
            }, insert: function (j) {
                var f = e;
                var g = [j];
                while (g.length) {
                    var h = g.shift();
                    var m = h._m || h.m;
                    var p = c._whichQuad(h, f);
                    if (f[p] === undefined) {
                        f[p] = h;
                        f.mass += m;
                        if (f.p) {
                            f.p = f.p.add(h.p.multiply(m))
                        } else {
                            f.p = h.p.multiply(m)
                        }
                    } else {
                        if ("origin" in f[p]) {
                            f.mass += (m);
                            if (f.p) {
                                f.p = f.p.add(h.p.multiply(m))
                            } else {
                                f.p = h.p.multiply(m)
                            }
                            f = f[p];
                            g.unshift(h)
                        } else {
                            var l = f.size.divide(2);
                            var n = new Point(f.origin);
                            if (p[0] == "s") {
                                n.y += l.y
                            }
                            if (p[1] == "e") {
                                n.x += l.x
                            }
                            var o = f[p];
                            f[p] = c._newBranch();
                            f[p].origin = n;
                            f[p].size = l;
                            f.mass = m;
                            f.p = h.p.multiply(m);
                            f = f[p];
                            if (o.p.x === h.p.x && o.p.y === h.p.y) {
                                var k = l.x * 0.08;
                                var i = l.y * 0.08;
                                o.p.x = Math.min(n.x + l.x, Math.max(n.x, o.p.x - k / 2 + Math.random() * k));
                                o.p.y = Math.min(n.y + l.y, Math.max(n.y, o.p.y - i / 2 + Math.random() * i))
                            }
                            g.push(o);
                            g.unshift(h)
                        }
                    }
                }
            }, applyForces: function (m, g) {
                var f = [e];
                while (f.length) {
                    node = f.shift();
                    if (node === undefined) {
                        continue
                    }
                    if (m === node) {
                        continue
                    }
                    if ("f" in node) {
                        var k = m.p.subtract(node.p);
                        var l = Math.max(1, k.magnitude());
                        var i = ((k.magnitude() > 0) ? k : Point.random(1)).normalize();
                        m.applyForce(i.multiply(g * (node._m || node.m)).divide(l * l))
                    } else {
                        var j = m.p.subtract(node.p.divide(node.mass)).magnitude();
                        var h = Math.sqrt(node.size.x * node.size.y);
                        if (h / j > d) {
                            f.push(node.ne);
                            f.push(node.nw);
                            f.push(node.se);
                            f.push(node.sw)
                        } else {
                            var k = m.p.subtract(node.p.divide(node.mass));
                            var l = Math.max(1, k.magnitude());
                            var i = ((k.magnitude() > 0) ? k : Point.random(1)).normalize();
                            m.applyForce(i.multiply(g * (node.mass)).divide(l * l))
                        }
                    }
                }
            }, _whichQuad: function (i, f) {
                if (i.p.exploded()) {
                    return null
                }
                var h = i.p.subtract(f.origin);
                var g = f.size.divide(2);
                if (h.y < g.y) {
                    if (h.x < g.x) {
                        return "nw"
                    } else {
                        return "ne"
                    }
                } else {
                    if (h.x < g.x) {
                        return "sw"
                    } else {
                        return "se"
                    }
                }
            }, _newBranch: function () {
                if (b[a]) {
                    var f = b[a];
                    f.ne = f.nw = f.se = f.sw = undefined;
                    f.mass = 0;
                    delete f.p
                } else {
                    f = {origin: null, size: null, nw: undefined, ne: undefined, sw: undefined, se: undefined, mass: 0};
                    b[a] = f
                }
                a++;
                return f
            }
        };
        return c
    };
    /*    physics.js */
    var Physics = function (a, m, n, e, h) {
        var f = BarnesHutTree();
        var c = {particles: {}, springs: {}};
        var l = {particles: {}};
        var o = [];
        var k = [];
        var d = 0;
        var b = {sum: 0, max: 0, mean: 0};
        var g = {topleft: new Point(-1, -1), bottomright: new Point(1, 1)};
        var j = 1000;
        var i = {
            stiffness: (m !== undefined) ? m : 1000,
            repulsion: (n !== undefined) ? n : 600,
            friction: (e !== undefined) ? e : 0.3,
            gravity: false,
            dt: (a !== undefined) ? a : 0.02,
            theta: 0.4,
            init: function () {
                return i
            },
            modifyPhysics: function (p) {
                $.each(["stiffness", "repulsion", "friction", "gravity", "dt", "precision"], function (r, s) {
                    if (p[s] !== undefined) {
                        if (s == "precision") {
                            i.theta = 1 - p[s];
                            return
                        }
                        i[s] = p[s];
                        if (s == "stiffness") {
                            var q = p[s];
                            $.each(c.springs, function (u, t) {
                                t.k = q
                            })
                        }
                    }
                })
            },
            addNode: function (u) {
                var t = u.id;
                var q = u.m;
                var p = g.bottomright.x - g.topleft.x;
                var s = g.bottomright.y - g.topleft.y;
                var r = new Point((u.x != null) ? u.x : g.topleft.x + p * Math.random(), (u.y != null) ? u.y : g.topleft.y + s * Math.random());
                c.particles[t] = new Particle(r, q);
                c.particles[t].connections = 0;
                c.particles[t].fixed = (u.f === 1);
                l.particles[t] = c.particles[t];
                o.push(c.particles[t])
            },
            dropNode: function (s) {
                var r = s.id;
                var q = c.particles[r];
                var p = $.inArray(q, o);
                if (p > -1) {
                    o.splice(p, 1)
                }
                delete c.particles[r];
                delete l.particles[r]
            },
            modifyNode: function (r, p) {
                if (r in c.particles) {
                    var q = c.particles[r];
                    if ("x" in p) {
                        q.p.x = p.x
                    }
                    if ("y" in p) {
                        q.p.y = p.y
                    }
                    if ("m" in p) {
                        q.m = p.m
                    }
                    if ("f" in p) {
                        q.fixed = (p.f === 1)
                    }
                    if ("_m" in p) {
                        if (q._m === undefined) {
                            q._m = q.m
                        }
                        q.m = p._m
                    }
                }
            },
            addSpring: function (t) {
                var s = t.id;
                var p = t.l;
                var r = c.particles[t.fm];
                var q = c.particles[t.to];
                if (r !== undefined && q !== undefined) {
                    c.springs[s] = new Spring(r, q, p, i.stiffness);
                    k.push(c.springs[s]);
                    r.connections++;
                    q.connections++;
                    delete l.particles[t.fm];
                    delete l.particles[t.to]
                }
            },
            dropSpring: function (s) {
                var r = s.id;
                var q = c.springs[r];
                q.point1.connections--;
                q.point2.connections--;
                var p = $.inArray(q, k);
                if (p > -1) {
                    k.splice(p, 1)
                }
                delete c.springs[r]
            },
            _update: function (p) {
                d++;
                $.each(p, function (q, r) {
                    if (r.t in i) {
                        i[r.t](r)
                    }
                });
                return d
            },
            tick: function () {
                i.tendParticles();
                i.eulerIntegrator(i.dt);
                i.tock()
            },
            tock: function () {
                var p = [];
                $.each(c.particles, function (r, q) {
                    p.push(r);
                    p.push(q.p.x);
                    p.push(q.p.y)
                });
                if (h) {
                    h({geometry: p, epoch: d, energy: b, bounds: g})
                }
            },
            tendParticles: function () {
                $.each(c.particles, function (q, p) {
                    if (p._m !== undefined) {
                        if (Math.abs(p.m - p._m) < 1) {
                            p.m = p._m;
                            delete p._m
                        } else {
                            p.m *= 0.98
                        }
                    }
                    p.v.x = p.v.y = 0
                })
            },
            eulerIntegrator: function (p) {
                if (i.repulsion > 0) {
                    if (i.theta > 0) {
                        i.applyBarnesHutRepulsion()
                    } else {
                        i.applyBruteForceRepulsion()
                    }
                }
                if (i.stiffness > 0) {
                    i.applySprings()
                }
                i.applyCenterDrift();
                if (i.gravity) {
                    i.applyCenterGravity()
                }
                i.updateVelocity(p);
                i.updatePosition(p)
            },
            applyBruteForceRepulsion: function () {
                $.each(c.particles, function (q, p) {
                    $.each(c.particles, function (s, r) {
                        if (p !== r) {
                            var u = p.p.subtract(r.p);
                            var v = Math.max(1, u.magnitude());
                            var t = ((u.magnitude() > 0) ? u : Point.random(1)).normalize();
                            p.applyForce(t.multiply(i.repulsion * (r._m || r.m) * 0.5).divide(v * v * 0.5));
                            r.applyForce(t.multiply(i.repulsion * (p._m || p.m) * 0.5).divide(v * v * -0.5))
                        }
                    })
                })
            },
            applyBarnesHutRepulsion: function () {
                if (!g.topleft || !g.bottomright) {
                    return
                }
                var q = new Point(g.bottomright);
                var p = new Point(g.topleft);
                f.init(p, q, i.theta);
                $.each(c.particles, function (s, r) {
                    f.insert(r)
                });
                $.each(c.particles, function (s, r) {
                    f.applyForces(r, i.repulsion)
                })
            },
            applySprings: function () {
                $.each(c.springs, function (t, p) {
                    var s = p.point2.p.subtract(p.point1.p);
                    var q = p.length - s.magnitude();
                    var r = ((s.magnitude() > 0) ? s : Point.random(1)).normalize();
                    p.point1.applyForce(r.multiply(p.k * q * -0.5));
                    p.point2.applyForce(r.multiply(p.k * q * 0.5))
                })
            },
            applyCenterDrift: function () {
                var q = 0;
                var r = new Point(0, 0);
                $.each(c.particles, function (t, s) {
                    r.add(s.p);
                    q++
                });
                if (q == 0) {
                    return
                }
                var p = r.divide(-q);
                $.each(c.particles, function (t, s) {
                    s.applyForce(p)
                })
            },
            applyCenterGravity: function () {
                $.each(c.particles, function (r, p) {
                    var q = p.p.multiply(-1);
                    p.applyForce(q.multiply(i.repulsion / 100))
                })
            },
            updateVelocity: function (p) {
                $.each(c.particles, function (t, q) {
                    if (q.fixed) {
                        q.v = new Point(0, 0);
                        q.f = new Point(0, 0);
                        return
                    }
                    var s = q.v.magnitude();
                    q.v = q.v.add(q.f.multiply(p)).multiply(1 - i.friction);
                    q.f.x = q.f.y = 0;
                    var r = q.v.magnitude();
                    if (r > j) {
                        q.v = q.v.divide(r * r)
                    }
                })
            },
            updatePosition: function (q) {
                var r = 0, p = 0, u = 0;
                var t = null;
                var s = null;
                $.each(c.particles, function (w, v) {
                    v.p = v.p.add(v.v.multiply(q));
                    var x = v.v.magnitude();
                    var z = x * x;
                    r += z;
                    p = Math.max(z, p);
                    u++;
                    if (!t) {
                        t = new Point(v.p.x, v.p.y);
                        s = new Point(v.p.x, v.p.y);
                        return
                    }
                    var y = v.p;
                    if (y.x === null || y.y === null) {
                        return
                    }
                    if (y.x > t.x) {
                        t.x = y.x
                    }
                    if (y.y > t.y) {
                        t.y = y.y
                    }
                    if (y.x < s.x) {
                        s.x = y.x
                    }
                    if (y.y < s.y) {
                        s.y = y.y
                    }
                });
                b = {sum: r, max: p, mean: r / u, n: u};
                g = {topleft: s || new Point(-1, -1), bottomright: t || new Point(1, 1)}
            },
            systemEnergy: function (p) {
                return b
            }
        };
        return i.init()
    };
    var _nearParticle = function (b, c) {
        var c = c || 0;
        var a = b.x;
        var f = b.y;
        var e = c * 2;
        return new Point(a - c + Math.random() * e, f - c + Math.random() * e)
    };

    // if called as a worker thread, set up a run loop for the Physics object and bail out
    if (typeof(window) == 'undefined') return (function () {
        /* hermetic.js */
        $ = {
            each: function (d, e) {
                if ($.isArray(d)) {
                    for (var c = 0, b = d.length; c < b; c++) {
                        e(c, d[c])
                    }
                } else {
                    for (var a in d) {
                        e(a, d[a])
                    }
                }
            }, map: function (a, c) {
                var b = [];
                $.each(a, function (f, e) {
                    var d = c(e);
                    if (d !== undefined) {
                        b.push(d)
                    }
                });
                return b
            }, extend: function (c, b) {
                if (typeof b != "object") {
                    return c
                }
                for (var a in b) {
                    if (b.hasOwnProperty(a)) {
                        c[a] = b[a]
                    }
                }
                return c
            }, isArray: function (a) {
                if (!a) {
                    return false
                }
                return (a.constructor.toString().indexOf("Array") != -1)
            }, inArray: function (c, a) {
                for (var d = 0, b = a.length; d < b; d++) {
                    if (a[d] === c) {
                        return d
                    }
                }
                return -1
            }, isEmptyObject: function (a) {
                if (typeof a !== "object") {
                    return false
                }
                var b = true;
                $.each(a, function (c, d) {
                    b = false
                });
                return b
            }
        };
        /*     worker.js */
        var PhysicsWorker = function () {
            var b = 20;
            var a = null;
            var d = null;
            var c = null;
            var g = [];
            var f = new Date().valueOf();
            var e = {
                init: function (h) {
                    e.timeout(h.timeout);
                    a = Physics(h.dt, h.stiffness, h.repulsion, h.friction, e.tock);
                    return e
                }, timeout: function (h) {
                    if (h != b) {
                        b = h;
                        if (d !== null) {
                            e.stop();
                            e.go()
                        }
                    }
                }, go: function () {
                    if (d !== null) {
                        return
                    }
                    c = null;
                    d = setInterval(e.tick, b)
                }, stop: function () {
                    if (d === null) {
                        return
                    }
                    clearInterval(d);
                    d = null
                }, tick: function () {
                    a.tick();
                    var h = a.systemEnergy();
                    if ((h.mean + h.max) / 2 < 0.05) {
                        if (c === null) {
                            c = new Date().valueOf()
                        }
                        if (new Date().valueOf() - c > 1000) {
                            e.stop()
                        } else {
                        }
                    } else {
                        c = null
                    }
                }, tock: function (h) {
                    h.type = "geometry";
                    postMessage(h)
                }, modifyNode: function (i, h) {
                    a.modifyNode(i, h);
                    e.go()
                }, modifyPhysics: function (h) {
                    a.modifyPhysics(h)
                }, update: function (h) {
                    var i = a._update(h)
                }
            };
            return e
        };
        var physics = PhysicsWorker();
        onmessage = function (a) {
            if (!a.data.type) {
                postMessage("¿kérnèl?");
                return
            }
            if (a.data.type == "physics") {
                var b = a.data.physics;
                physics.init(a.data.physics);
                return
            }
            switch (a.data.type) {
                case"modify":
                    physics.modifyNode(a.data.id, a.data.mods);
                    break;
                case"changes":
                    physics.update(a.data.changes);
                    physics.go();
                    break;
                case"start":
                    physics.go();
                    break;
                case"stop":
                    physics.stop();
                    break;
                case"sys":
                    var b = a.data.param || {};
                    if (!isNaN(b.timeout)) {
                        physics.timeout(b.timeout)
                    }
                    physics.modifyPhysics(b);
                    physics.go();
                    break
            }
        };
    })()


    arbor = (typeof(arbor) !== 'undefined') ? arbor : {}
    $.extend(arbor, {
        // object constructors (don't use ‘new’, just call them)
        ParticleSystem: ParticleSystem,
        Point: function (x, y) {
            return new Point(x, y)
        },

        // immutable object with useful methods
        etc: {
            trace: trace,              // ƒ(msg) -> safe console logging
            dirname: dirname,          // ƒ(path) -> leading part of path
            basename: basename,        // ƒ(path) -> trailing part of path
            ordinalize: ordinalize,    // ƒ(num) -> abbrev integers (and add commas)
            objcopy: objcopy,          // ƒ(old) -> clone an object
            objcmp: objcmp,            // ƒ(a, b, strict_ordering) -> t/f comparison
            objkeys: objkeys,          // ƒ(obj) -> array of all keys in obj
            objmerge: objmerge,        // ƒ(dst, src) -> like $.extend but non-destructive
            uniq: uniq,                // ƒ(arr) -> array of unique items in arr
            arbor_path: arbor_path    // ƒ() -> guess the directory of the lib code
        }
    })

})(this.jQuery)