
let div = document.querySelector("#content")
fetch('./docs/test.md')
    .then(function (response) {
        return response.text();
    })
    .then(function(txt){
        console.log(txt);
        div.innerHTML = marked(txt)
    })
