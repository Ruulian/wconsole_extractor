const express = require("express");
const app = express();
const path = require('path');
const fs = require('fs')
const port = 3000;

app.set('view engine', 'ejs');
app.use(express.static(path.join(__dirname, 'public')));


app.get('/', (req,res) => {
    res.render('index');
});

app.get('/about', (req,res) => {
    res.render('about');
});

app.get('/file',(req,res) => {
    if (req.query.search){
        fs.readFile(req.query.search, 'utf-8', (err,data) => {
            if (err) {
                res.render('file', {content: 'File not found'});
                return;
            }
            res.render('file', {content: data});
        });
    } else {
        res.render('file', {content: "Search"});
    }
    
    
})

app.listen(port, () => {
    console.log(`Listening on port ${port}`);
})