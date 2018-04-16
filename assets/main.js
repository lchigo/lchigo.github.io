

function initCategories(categories) {
    const nav = document.querySelector(".menu")
    categories.sort((a, b) => {
        return a.name > b.name
    })
    categories.forEach(
        category => {
            const a = document.createElement("a")
            a.className = "menu-item"
            a.href = "#"
            a.innerHTML = category.name
            nav.appendChild(a)
        }
    )
}

function loadArticles(articles) {
    const content = document.querySelector("#content")
    articles.forEach(
        article => {
            const div = document.createElement("div")
            fetch(article.path).then(response => {
                return response.text()
            }).then(text => {
                div.innerHTML = marked(text)
                content.appendChild(div)
            })
        }
    )
}

function main() {
    const content = document.querySelector("#content")
    fetch('config.json')
        .then(response => {
            return response.json()
        })
        .then(config => {
            console.log(config)
            initCategories(config.categories)
            return config
        }).then(config => {
            loadArticles(config.articles)
        })
}

main()