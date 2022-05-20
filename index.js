const express = require('express');
const app = express();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const pg = require('pg');

app.use(express.urlencoded({ extended: false })); 
app.use(express.json());

var conString = 'postgres://uzkrifhyfuynru:7ae68169aa2c1665db6001a2b26c7d54f4b9a0f1e4fb782622aaf1ba2c136f58@ec2-54-204-56-171.compute-1.amazonaws.com:5432/ddmu666c1rg0uu';

const pool = new pg.Pool({connectionString: conString, ssl: {rejectUnauthorized: false}});

//USUARIOS

//rota principal -teste de rota
app.get('/', (req, res) => {
    pool.connect((err, client) => {
        if (err) {
            return res.status(401).send('Não foi possível conectar')
        }
        res.status(200).send('Conectado com sucesso')
    })
})

//cadastrar
app.post('/cadusuarios', (req, res) => {
    pool.connect((err, client) => {
        if (err) {
            return res.status(401).send('Conexão nao autorizada')
        }

        client.query('select * from usuarios where cpf = $1', [req.body.cpf], (error, result) => {
            if (error) {
                return res.status(401).send('Operação não autorizada')
            }

            if (result.rowCount > 0) {
                return res.status(200).send('Usuário já cadastrado')
            }
            bcrypt.hash(req.body.senha, 10, (error, hash) => {
                if (error) {
                    return res.status(500).send({
                        message: 'Erro de autenticação',
                        erro: error.message
                    })
                }
                var sql = 'INSERT INTO usuarios (nome, email, senha, cpf, fone, cep, pais, estado, cidade, bairro, rua, numero, complemento, perfil) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)';
                var valores = [req.body.nome, req.body.email, hash, req.body.cpf, req.body.fone, req.body.cep, req.body.pais, req.body.estado, req.body.cidade, req.body.bairro, req.body.rua, req.body.numero, req.body.complemento, req.body.perfil];

                client.query(sql, valores, (error, result) => {
                    if (error) {
                        return res.status(403).send(error);
                    }
                    if (result) {
                        res.status(201).send({
                            mensagem: 'Usuário cadastrado com sucesso',
                            status: 201
                        })
                        
                    }
                })
            })
        })
    })
})


//listando perfis cadastrados
app.get('/usuarios', (req, res) => {
    pool.connect((err, client) => {
        if (err) {
           return res.status(401).send('Conexão não autorizada')
        }

        client.query('select * from usuarios', (error, result) => {
            if (error) {
                return res.status(401).send('Operação não autorizada')
            }
             return res.status(200).send(result.rows)
        })
    })
})

//consulta de perfis por id
app.get('/usuarios/:id', (req, res) => {
    pool.connect((err, client) => {
        if (err) {
            return res.status(401).send('Conexão não autorizada')
        }
        client.query('select * from usuarios where id = $1', [req.params.id], (error, result) => {
            if (error) {
                return res.status(401).send('Operação não autorizada')
            }
            res.status(200).send(result.rows[0])
        })
    })
})


//update
app.put('/usuarios/:id', (req, res) => {
    pool.connect((err, client) => {
        if (err) {
            return res.status(401).send('Conexão não autorizada')
        }
        client.query('select * from usuarios where id=$1', [req.params.id], (error, result) => {
            if (error) {
                return res.status(401).send('Operação não permitida')
            }

            //update usuarios set nome=$1, email =$2, senha=$3, cpf=$4, fone=$5, cep=$6, pais=$7, estado=$8, cidade=$9, bairro=$10, rua=$11, numero=$12, complemento=$13, perfil=$14
            if (result.rowCount > 0) {
                var sql = 'update usuarios set nome=$1, email =$2, senha=$3, cpf=$4, fone=$5, cep=$6, pais=$7, estado=$8, cidade=$9, bairro=$10, rua=$11, numero=$12, complemento=$13, perfil=$14 where id=$15'
                let valores = [req.body.nome, req.body.email, req.body.senha, req.body.cpf, req.body.fone, req.body.cep, req.body.pais, req.body.estado, req.body.cidade, req.body.bairro, req.body.rua, req.body.numero, req.body.complemento, req.body.perfil, req.params.id];

                client.query(sql, valores, (error2, result2) => {
                    if (error2) {
                        return res.status(401).send(error2)
                    }

                    if (result2.rowCount > 0) {
                        return res.status(200).send('Dados alterados com sucesso')
                    }
                })
            } else {
                res.status(200).send('User não encontrado')
            }

        })
    })
})

//metodo deletar
app.delete('/usuarios/:id', (req, res) => {
    pool.connect((err, client) => {
        if (err) {
            return res.status(401).send('Conexão não autorizada')
        }

        client.query('delete from usuarios where id = $1', [req.params.id], (error, result) => {

            if (error) {
                return res.status(401).send('Operação não autorizada')
            }
            res.status(200).send({
                message: 'Usuário excluído com sucesso'
            })
        })
    })
})


//login
app.post('/usuarios/login', (req, res) => {
    //res.status(200).send('buscar usuário')
    pool.connect((err, client) => {
        if (err) {
            return res.status(401).send("Conexão não autorizada")
        }
        client.query(' select * from usuarios where email = $1', [req.body.email], (error, result) => {
            if (error) {
                return res.status(401).send('operação nao permitida')
            }
            if (result.rowCount > 0) {
                //criptografar a senha enviada e comparar com a recuperada
                bcrypt.compare(req.body.senha, result.rows[0].senha, (error, results) => {
                    if (error) {
                        return res.status(401).send({
                            message: "Falha na autenticação"
                        })
                    }
                    if (results) {
                        let token = jwt.sign({
                                email: result.rows[0].email,
                                perfil: result.rows[0].perfil
                            },
                            process.env.JWTKEY, {
                                expiresIn: '1h'
                            })
                        return res.status(200).send({
                            message: 'Conectado com sucesso',
                            token: token
                        })
                    }
                })
            } else {
                return res.status(200).send({
                    message: 'usuário não encontrado'
                })
            }
        })
    })
})

// ----------------- PRODUTOS ------------------------
//CADASTRO DE NOVOS PRODUTOS
app.post('/cadprodutos', (req, res) => {
    pool.connect((err, product) =>{
        if (err) {
            return res.status(401).send('Conexão nao autorizada')
        }
        
        product.query('select * from produtos where id = $1', [req.body.id], (error,result) =>{
            if (error) {
                return res.status(401).send('Operação não autorizada')
            }

            if (result.rowCount > 0) {
                return res.status(200).send('Produto cadastrado')
            }

             var sql = 'INSERT INTO produtos(categoria, preco, foto, descricao) VALUES ($1, $2, $3, $4)'

            product.query(sql,[req.body.categoria, req.body.preco, req.body.foto, req.body.descricao], (error, result) => {
                if (error) {
                    return res.status(403).send('Operação não permitida')
            }

            res.status(201).send({
                mensagem: 'Produto cadastrado com sucesso',
                status: 201
            })
            
            })
        
        }) 
        
    })
})

//LISTANDO PRODUTOS
app.get('/produtos', (req, res) => {
    pool.connect((err, product) => {
        if(err){
            res.status(401).send('Conexão não autorizada')
        }

        product.query('select * from produtos', (error, result) => {
            if(error) {
               return res.status(401).send('Operação não autorizada')
            }
            res.status(200).send(result.rows)
        })
    })
})

//PESQUISA DE PRODUTO POR ID
//(tentar add um aviso caso nao exista o id buscado)
app.get('/produtos/:id', (req, res) =>{
    pool.connect((err, product) => {
        if (err) {
            return res.status(401).send('Conexão não autorizada')
         }
         product.query('select * from produtos where id = $1', [req.params.id], (error, result) =>{
             if(error) {
                 return res.status(401).send('Operação não autorizada')
             }
             res.status(200).send(result.rows[0])
         })
    })
})

//DELETAR PRODUTOS
app.delete('/produtos/:id', (req, res) =>{
    pool.connect((err, product) => {
        if (err) {
           return res.status(401).send('Conexão não autorizada')
        }

        product.query('delete from produtos where id = $1', [req.params.id], (error, result) =>{

            if (error) {
                return res.status(401).send('Operação não autorizada')
            }
                res.status(200).send({message: 'Produto excluído com sucesso'})
        })
    })
})

//UPDATE DE PRODUTOS
app.put('/cadprodutos/:id', (req, res) => {
    pool.connect((err, product) =>{
        if (err){
            return res.status(401).send('Conexão não autorizada')
        }
        product.query('select * from produtos where id =$1', [req.params.id], (error, result) =>{
            if (error){
                return res.status(401).send('Operação não permitida')
            }

            //update produtos set  categoria=$1, preco=$2, foto=$3, descricao=$4 where id=$5
            if (result.rowCount > 0) {
                var sql = 'update produtos set  categoria=$1, preco=$2, foto=$3, descricao=$4 where id=$5'
                let valores = [req.body.categoria, req.body.preco, req.body.foto, req.body.drescricao, req.params.id]
                
                product.query(sql, valores, (error2, result2) =>{
                    if(error2) {
                        return res.status(401).send('Operação não permitida')
                    }

                    if(result2.rowCount > 0) {
                        return res.status(200).send('Dados alterados com sucesso')
                    }
                })
            } else {
                res.status(200).send('Produto não encontrado')
            }

        })
    })
})

const PORT = process.env.PORT||'8080';
app.listen(PORT, () => console.log(`aplicação em execução na url http://localhost:${PORT}`));