
let div = document.querySelector("#content")
fetch('./docs/test.md')
    .then(function (response) {
        let txt = response.text();
        console.log(txt);
        div.innerHTML = marked(txt)
    })
