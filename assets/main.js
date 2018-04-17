

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
    const articlePaths = []
    articles.forEach(
        article => {
            articlePaths.push(article.path)
        }
    )
    fetchByOrder(articlePaths, 0, text => {
        window.txt = text
        const div = document.createElement("div")
        div.className = "article markdown-body"
        div.innerHTML = marked(text, { highlight: code => { return hljs.highlightAuto(code).value } })
        content.appendChild(div)
    })
}

function fetchByOrder(urls, index, callback) {
    if (index == urls.length) {
        return
    }
    fetch(urls[index])
        .then(response => {
            return response.text()
        }
        ).then(text => {
            callback(text)
            fetchByOrder(urls, index + 1, callback)
        })
}

function main() {
    const content = document.querySelector("#content")
    // hljs.initHighlightingOnLoad()
    fetch('config.json')
        .then(response => {
            return response.json()
        })
        .then(config => {
            initCategories(config.categories)
            return config
        }).then(config => {
            loadArticles(config.articles)
        })
}

main()