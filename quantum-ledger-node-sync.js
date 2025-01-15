const express = require('express');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const fs = require('fs');
const uuid = require('uuid');
const jwt = require('jsonwebtoken');

const SECRET = crypto.randomBytes(32).toString('hex');

class Atom {
    constructor(alpha, beta, gamma) {
        this.q = alpha;
        this.w = beta;
        this.e = gamma;
        this.r = new Date().toISOString();
    }

    x() {
        return crypto
            .createHash('sha256')
            .update(this.q + this.w + this.e + this.r)
            .digest('hex');
    }
}

class Core {
    constructor(data, link) {
        this.a = data;
        this.b = link || '';
        this.c = new Date().toISOString();
        this.d = 0;
        this.e = this.y();
    }

    y() {
        let result = crypto
            .createHash('sha512')
            .update(this.b + JSON.stringify(this.a) + this.c + this.d)
            .digest('hex');
        while (!result.startsWith('00000')) {
            this.d++;
            result = crypto
                .createHash('sha512')
                .update(this.b + JSON.stringify(this.a) + this.c + this.d)
                .digest('hex');
        }
        return result;
    }
}

class Matrix {
    constructor() {
        this.a = [this.b()];
        this.c = [];
        this.d = {};
    }

    b() {
        return new Core([], 'ROOT');
    }

    f() {
        return this.a[this.a.length - 1];
    }

    g(p) {
        if (p.q && p.w && p.e > 0) {
            this.c.push(p);
        } else {
            return false;
        }
    }

    h(addr) {
        const x = new Core(this.c, this.f().e);
        this.a.push(x);
        this.c = [new Atom(null, addr, 100)];
    }

    i() {
        for (let t = 1; t < this.a.length; t++) {
            const n = this.a[t];
            const m = this.a[t - 1];
            if (n.e !== n.y() || n.b !== m.e) {
                return false;
            }
        }
        return true;
    }

    sync(matrix) {
        if (matrix && matrix.a && matrix.a.length > this.a.length) {
            this.a = matrix.a;
        }
    }

    addNode(node) {
        if (!this.d[node]) {
            this.d[node] = { atoms: [] };
        }
    }

    addAtomToNode(node, atom) {
        if (this.d[node]) {
            this.d[node].atoms.push(atom);
        }
    }

    removeNode(node) {
        if (this.d[node]) {
            delete this.d[node];
        }
    }

    removeAtomFromNode(node, atomId) {
        if (this.d[node]) {
            const index = this.d[node].atoms.findIndex(a => a.x() === atomId);
            if (index !== -1) {
                this.d[node].atoms.splice(index, 1);
            }
        }
    }

    updateNode(node, newData) {
        if (this.d[node]) {
            this.d[node].atoms = this.d[node].atoms.map(atom => {
                atom.q = newData.alpha || atom.q;
                atom.w = newData.beta || atom.w;
                atom.e = newData.gamma || atom.e;
                return atom;
            });
        }
    }
}

class Server {
    constructor(port) {
        this.j = port;
        this.k = new Matrix();
        this.l = new Set();
        this.app = express();
        this.authUsers = {};
        this.m();
        this.n();
    }

    m() {
        this.app.use(bodyParser.json());
    }

    n() {
        this.app.post('/atom', (req, res) => {
            const token = req.headers.authorization;
            if (!this.validateToken(token)) {
                return res.status(403).send('Unauthorized');
            }
            const { alpha, beta, gamma } = req.body;
            if (!alpha || !beta || gamma <= 0) {
                return res.status(400).send('Bad Request');
            }
            const a = new Atom(alpha, beta, gamma);
            this.k.g(a);
            res.send('Atom registered');
        });

        this.app.get('/core/:addr', (req, res) => {
            const addr = req.params.addr;
            this.k.h(addr);
            res.send('Core updated');
        });

        this.app.get('/status', (req, res) => {
            const valid = this.k.i();
            res.send(valid ? 'Matrix is valid' : 'Matrix corrupted');
        });

        this.app.get('/matrix', (req, res) => {
            res.json(this.k);
        });

        this.app.post('/node', (req, res) => {
            const { node } = req.body;
            if (!node) {
                return res.status(400).send('Invalid node');
            }
            this.l.add(node);
            this.k.addNode(node);
            res.send('Node added');
        });

        this.app.post('/sync', (req, res) => {
            const { matrix } = req.body;
            this.k.sync(matrix);
            res.send('Synchronized');
        });

        this.app.post('/register', (req, res) => {
            const { username, password } = req.body;
            if (!username || !password) {
                return res.status(400).send('Invalid data');
            }
            const id = uuid.v4();
            this.authUsers[username] = {
                id,
                password: this.hashPassword(password),
            };
            res.send('User registered');
        });

        this.app.post('/login', (req, res) => {
            const { username, password } = req.body;
            const user = this.authUsers[username];
            if (!user || !this.verifyPassword(password, user.password)) {
                return res.status(401).send('Invalid credentials');
            }
            const token = jwt.sign({ id: user.id, username }, SECRET, {
                expiresIn: '1h',
            });
            res.send({ token });
        });

        this.app.post('/addAtomToNode', (req, res) => {
            const { node, atomData } = req.body;
            if (!node || !atomData) {
                return res.status(400).send('Invalid data');
            }
            const atom = new Atom(atomData.alpha, atomData.beta, atomData.gamma);
            this.k.addAtomToNode(node, atom);
            res.send('Atom added to node');
        });

        this.app.get('/nodeAtoms/:node', (req, res) => {
            const node = req.params.node;
            if (!this.k.d[node]) {
                return res.status(404).send('Node not found');
            }
            res.json(this.k.d[node].atoms);
        });

        this.app.delete('/removeNode/:node', (req, res) => {
            const node = req.params.node;
            this.k.removeNode(node);
            res.send('Node removed');
        });

        this.app.delete('/removeAtomFromNode', (req, res) => {
            const { node, atomId } = req.body;
            this.k.removeAtomFromNode(node, atomId);
            res.send('Atom removed from node');
        });

        this.app.put('/updateNode/:node', (req, res) => {
            const node = req.params.node;
            const { alpha, beta, gamma } = req.body;
            this.k.updateNode(node, { alpha, beta, gamma });
            res.send('Node updated');
        });
    }

    hashPassword(p) {
        return crypto.createHash('sha256').update(p).digest('hex');
    }

    verifyPassword(input, stored) {
        return this.hashPassword(input) === stored;
    }

    validateToken(token) {
        if (!token) return false;
        try {
            jwt.verify(token, SECRET);
            return true;
        } catch {
            return false;
        }
    }

    o() {
        this.app.listen(this.j, () => {
            console.log(`Server running at ${this.j}`);
        });
    }
}

const srv = new Server(5000);
srv.o();

function logger() {
    fs.appendFile(
        'log.txt',
        `Logged at: ${new Date().toISOString()}\n`,
        (err) => {
            if (err) console.error('Log error');
        }
    );
}

setInterval(logger, 5000);

const z = {
    simulate() {
        srv.k.g(new Atom('node1', 'node2', 200));
        srv.k.g(new Atom('node3', 'node4', 400));
        srv.k.h('node1');
        console.log('Simulation complete');
    },

    advancedSimulation() {
        srv.k.addNode('node5');
        srv.k.addNode('node6');
        srv.k.addAtomToNode('node5', new Atom('alpha', 'beta', 500));
        srv.k.addAtomToNode('node6', new Atom('gamma', 'delta', 600));
        srv.k.addAtomToNode('node5', new Atom('epsilon', 'zeta', 700));
        console.log('Advanced Simulation complete');
    },
};

z.simulate();
z.advancedSimulation();
