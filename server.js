const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const User = require ('./model/user');
const bcrypt  = require('bcryptjs');
const jwt = require('jsonwebtoken');
// const { response } = require('express');

const JWT_SECRET = 'totototo';

//DB
mongoose.connect('mongodb+srv://admin:admin@cluster0.iutbg.mongodb.net/Permis?retryWrites=true&w=majority', {
    useNewUrlParser: true, 
    // useFindAndModify: true,
    useUnifiedTopology: true,
    useCreateIndex: true
}).then(() => console.log("connected"))
.catch(err => console.log("DB connection error: ",err));


const app = express();
app.use('/', express.static(path.join(__dirname, 'static')))
app.use(bodyParser.json())

app.post('/api/change-password', async (req, res) => {
    const { token, newpassword: plainTextPassword } = req.body

    if(!plainTextPassword || typeof plainTextPassword !== 'string' ){
        return res.json({ status: 'error', error:'Invalid password' })
    }

    if(plainTextPassword.length < 5){
        return res.json({ 
            status: 'error', 
            error:'Password to small,Should be atleast 6 character' 
        })
    }

    try{
        const user = jwt.verify(token, JWT_SECRET)
        //...
        // console.log(user)
        const _id = user.id

        const password = await bcrypt.hash(plainTextPassword, 10)
        await User.updateOne({ _id },
            {
                $set: { password }
            })
            res.json({ status: 'ok' })
    }catch(error){
        console.log(error)
        res.json({ status: 'error', error: ';))'})
    }
    
    // console.log('JWT decoded: ', user)
    // res.json({ status: 'ok'})
})

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body
    // const user = await User.findOne({ username, password }).lean()
    const user = await User.findOne({ username }).lean()

    if(!user){
        return res.json({ status: 'error', error: 'Invalide username/password'})
    }

    if(await bcrypt.compare(password, user.password)) {
        const token = jwt.sign(
            { 
                id: user._id, 
                username: user.username 
            },
            JWT_SECRET
        )
        return res.json({ status: 'ok', data: token})
    }


    res.json({ status: 'error', data: 'Invalide username/password' })
})

app.post('/api/register', async (req, res) => {
    // console.log(req.body);

    const { username, password: plainTextPassword } = req.body;

    if(!username || typeof username !== 'string' ){
        return res.json({ status: 'error', error:'Invalid username' })
    }

    if(!plainTextPassword || typeof plainTextPassword !== 'string' ){
        return res.json({ status: 'error', error:'Invalid password' })
    }

    if(plainTextPassword.length < 5){
        return res.json({ 
            status: 'error', 
            error:'Password to small,Should be atleast 6 character' 
        })
    }

    const password = await bcrypt.hash(plainTextPassword, 10)

    try{
        const response = await User.create({
            username,
            password
        })
        console.log('User Created Successfully: ',response)
    }catch(error){
        // console.log(error.message)
        // console.log(JSON.stringify(error))
        if(error.code === 11000){
            //duplicate key
            return res.json({ status: 'error', error: 'User Name already use' })
        }
        throw error
        
    }

    // console.log(await bcrypt.hash(password, 10))

    res.json({ status: 'ok' })
})

app.listen(9999, () => {
    console.log('Server up at 9999')
})