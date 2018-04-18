function createNode(nodeName, attributes) {
    const node = document.createElement(nodeName)
    const map = new Map(Object.entries(attributes));
    map.forEach((k, v) => {
        node[v] = k
    })
    return node
}

function showViews() {

    const contents = document.querySelector("#contents")
    const mark = document.querySelector("#mark")
    document.querySelectorAll(".mb-5.pb-5").forEach(e => {
        contents.removeChild(e)
    })

    const showArticle = (text, article) => {
        const box = createNode("div", { "className": "mb-5 pb-5" })
        const h1 = createNode("h1", { "className": "lh-condensed" })
        const a = createNode("a", {
            "id": article.id,
            "innerHTML": article.title
        })
        const ul = createNode("ul", { "className": "d-flex flex-wrap mt-1 mb-2 list-style-none text-gray" })
        const li = createNode("li", {
            "className": "my-1 mr-4 no-wrap",
            "innerHTML": "<span class='d-inline-block v-align-middle overflow-hidden mr-1 rounded-1' style='width: 20px; height: 20px;'>" +
                "<img src='data:image/svg+xml;base64,CjxzdmcgdmVyc2lvbj0iMS4xIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIiB4PSIwcHgiIHk9IjBweCIgdmlld0JveD0iMCAwIDEwMDAgMTAwMCIgZW5hYmxlLWJhY2tncm91bmQ9Im5ldyAwIDAgMTAwMCAxMDAwIiB4bWw6c3BhY2U9InByZXNlcnZlIj4KPG1ldGFkYXRhPiDnn6Lph4/lm77moIfkuIvovb0gOiBodHRwOi8vd3d3LnNmb250LmNuLyA8L21ldGFkYXRhPjxnPjxwYXRoIGQ9Ik03OTkuNyw4MS43SDY3OC4yVjQzLjVjMC0xOC41LTEzLjYtMzMuNS0zMC4yLTMzLjVjLTE2LjcsMC0zMC4yLDE1LTMwLjIsMzMuNXYzOC4ySDM4Mi4zVjQzLjVjMC0xOC41LTEzLjYtMzMuNS0zMC4yLTMzLjVjLTE2LjcsMC0zMC4yLDE1LTMwLjIsMzMuNXYzOC4ySDIwMC4zQzk1LjQsODEuNywxMCwxNzYuNCwxMCwyOTIuOHY0ODYuMUMxMCw4OTUuMyw5NS40LDk5MCwyMDAuMyw5OTBoNTk5LjVDOTA0LjYsOTkwLDk5MCw4OTUuMyw5OTAsNzc4LjlWMjkyLjhDOTkwLDE3Ni40LDkwNC42LDgxLjcsNzk5LjcsODEuN3ogTTIwMC4zLDExNS4yYzAsMCw4Mi4zLDAsMTIxLjYsMHY3OC40YzAsMTguNSwxMy42LDMzLjUsMzAuMiwzMy41YzE2LjcsMCwzMC4yLTE1LDMwLjItMzMuNXYtNzguNGM5OS42LDAsMTM1LjgsMCwyMzUuNCwwdjc4LjRjMCwxOC41LDEzLjYsMzMuNSwzMC4yLDMzLjVjMTYuNywwLDMwLjItMTUsMzAuMi0zMy41di03OC40YzM5LjMsMCwxMjEuNiwwLDEyMS42LDBjODguMiwwLDE2MCw3OS43LDE2MCwxNzcuNnY2MC43SDQwLjJ2LTYwLjdDNDAuMiwxOTQuOSwxMTIsMTE1LjIsMjAwLjMsMTE1LjJ6IE03OTkuNyw5NTYuNUgyMDAuM2MtODguMiwwLTE2MC03OS43LTE2MC0xNzcuNlYzODdoOTE5LjV2MzkyQzk1OS44LDg3Ni44LDg4OCw5NTYuNSw3OTkuNyw5NTYuNXoiPjwvcGF0aD48cGF0aCBkPSJNMTgzLjYsNTcxLjNjMCwzMi44LDI2LjYsNTkuMyw1OS4zLDU5LjNjMzIuOCwwLDU5LjMtMjYuNiw1OS4zLTU5LjNTMjc1LjcsNTEyLDI0Mi45LDUxMkMyMTAuMiw1MTIsMTgzLjYsNTM4LjUsMTgzLjYsNTcxLjNMMTgzLjYsNTcxLjN6Ij48L3BhdGg+PHBhdGggZD0iTTQ0MC43LDU3MS4zYzAsMzIuOCwyNi42LDU5LjMsNTkuMyw1OS4zYzMyLjgsMCw1OS4zLTI2LjYsNTkuMy01OS4zUzUzMi44LDUxMiw1MDAsNTEyQzQ2Ny4yLDUxMiw0NDAuNyw1MzguNSw0NDAuNyw1NzEuM0w0NDAuNyw1NzEuM3oiPjwvcGF0aD48cGF0aCBkPSJNNjk3LjcsNTcxLjNjMCwzMi44LDI2LjYsNTkuMyw1OS4zLDU5LjNjMzIuOCwwLDU5LjMtMjYuNiw1OS4zLTU5LjNTNzg5LjgsNTEyLDc1Ny4xLDUxMkM3MjQuMyw1MTIsNjk3LjcsNTM4LjUsNjk3LjcsNTcxLjN6Ij48L3BhdGg+PHBhdGggZD0iTTE4My42LDc3NC4zYzAsMzIuOCwyNi42LDU5LjMsNTkuMyw1OS4zYzMyLjgsMCw1OS4zLTI2LjYsNTkuMy01OS4zcy0yNi42LTU5LjMtNTkuMy01OS4zQzIxMC4yLDcxNC45LDE4My42LDc0MS41LDE4My42LDc3NC4zTDE4My42LDc3NC4zTDE4My42LDc3NC4zeiI+PC9wYXRoPjxwYXRoIGQ9Ik00NDAuNyw3NzQuM2MwLDMyLjgsMjYuNiw1OS4zLDU5LjMsNTkuM2MzMi44LDAsNTkuMy0yNi42LDU5LjMtNTkuM3MtMjYuNi01OS4zLTU5LjMtNTkuM0M0NjcuMiw3MTQuOSw0NDAuNyw3NDEuNSw0NDAuNyw3NzQuM0w0NDAuNyw3NzQuM0w0NDAuNyw3NzQuM3oiPjwvcGF0aD48cGF0aCBkPSJNNjk3LjcsNzc0LjNjMCwzMi44LDI2LjYsNTkuMyw1OS4zLDU5LjNjMzIuOCwwLDU5LjMtMjYuNiw1OS4zLTU5LjNzLTI2LjYtNTkuMy01OS4zLTU5LjNDNzI0LjMsNzE0LjksNjk3LjcsNzQxLjUsNjk3LjcsNzc0LjNMNjk3LjcsNzc0LjN6Ij48L3BhdGg+PC9nPjwvc3ZnPiAg'" +
                "height='16px' width='16px'> </span>" +
                article.date
        })
        const li2 = createNode("li", {
            "className": "my-1 mr-4 no-wrap",
            "innerHTML": "<span class='d-inline-block v-align-middle overflow-hidden mr-1 rounded-1' style='width: 20px; height: 20px;'>" +
                "<img src='data:image/svg+xml;base64,CjxzdmcgdmVyc2lvbj0iMS4xIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIiB4PSIwcHgiIHk9IjBweCIgdmlld0JveD0iMCAwIDEwMDAgMTAwMCIgZW5hYmxlLWJhY2tncm91bmQ9Im5ldyAwIDAgMTAwMCAxMDAwIiB4bWw6c3BhY2U9InByZXNlcnZlIj4KPG1ldGFkYXRhPiDnn6Lph4/lm77moIfkuIvovb0gOiBodHRwOi8vd3d3LnNmb250LmNuLyA8L21ldGFkYXRhPjxnPjxwYXRoIGQ9Ik05MzUuNiwxMEg2NC40QzM0LjUsMTAsMTAsMzQuNSwxMCw2NC40djg3MS4xYzAsMjkuOSwyNC41LDU0LjQsNTQuNCw1NC40aDg3MS4xYzI5LjksMCw1NC40LTI0LjUsNTQuNC01NC40VjY0LjRDOTkwLDM0LjUsOTY1LjUsMTAsOTM1LjYsMTB6IE05MzUuNiw5MzUuNkg2NC40VjY0LjRoODcxLjFWOTM1LjZ6IE0yOTUuOCwzMDkuNEgxODYuOVYyNTVoMTA4LjlWMzA5LjR6IE04MTMuMSwzMDkuNEgzNTAuM1YyNTVoNDYyLjhWMzA5LjR6IE0yOTUuOCw1MjcuMkgxODYuOXYtNTQuNGgxMDguOVY1MjcuMnogTTgxMy4xLDUyNy4ySDM1MC4zdi01NC40aDQ2Mi44VjUyNy4yeiBNMjk1LjgsNzQ1SDE4Ni45di01NC40aDEwOC45Vjc0NXogTTgxMy4xLDc0NUgzNTAuM3YtNTQuNGg0NjIuOFY3NDV6Ij48L3BhdGg+PC9nPjwvc3ZnPiAg'" +
                "height='16px' width='16px'> </span>" +
                article.category
        })

        ul.appendChild(li)
        ul.appendChild(li2)
        const content = createNode("div", {
            "className": "content markdown-body",
            "innerHTML": marked(text, { highlight: code => { return hljs.highlightAuto(code).value } })
        })
        h1.appendChild(a)
        box.appendChild(h1)
        box.appendChild(ul)
        box.appendChild(content)
        contents.insertBefore(box, mark)
    }
    const btns = document.querySelector('#pagebtn')
    if (window.pageInfo.pageArticles.length == 0) {
        btns.hidden = true
        return
    }
    fetchByOrder(window.pageInfo.pageArticles, 0, showArticle, () => { btns.hidden = false })
}

function fetchByOrder(articles, index, callback, finishCallback) {
    if (index == articles.length) {
        if (finishCallback) {
            finishCallback()
        }
        return
    }
    fetch(articles[index].path)
        .then(response => {
            return response.text()
        }
        ).then(text => {
            callback(text, articles[index])
            fetchByOrder(articles, index + 1, callback, finishCallback)
        })
}

function parseConfig(config) {
    const categoryMap = new Map()
    const articleMap = new Map()

    config.articles.forEach(article => {
        articleMap.set(article.id, article)
        if (categoryMap.has(article.category)) {
            categoryMap.get(article.category).push(article)
        } else {
            categoryMap.set(article.category, [article])
        }

    })

    window.categoryMap = categoryMap
    window.articleMap = articleMap
    window.allArticles = config.articles
    window.currentArticles = config.articles

}

function initPageInfo(page) {
    let currentPage = page
    let countPerPage = 2
    let total = window.currentArticles.length
    let lastPage = Math.floor(total / countPerPage)
    let pageArticles = []

    if (total % countPerPage == 0) {
        lastPage--
    }

    if (lastPage >= 0) {
        let start = currentPage * countPerPage
        let remain = countPerPage
        if ((currentPage == lastPage) && (total % countPerPage != 0)) {
            remain = total % countPerPage
        }
        for (let i = start; i < start + remain; i++) {
            pageArticles.push(window.currentArticles[i])
        }
    }

    window.pageInfo = {
        "currentPage": currentPage,
        "lastPage": lastPage,
        "countPerPage": countPerPage,
        "total": window.currentArticles.length,
        "pageArticles": pageArticles
    }

}

function initCategories() {
    const nav = document.querySelector(".menu")
    const mobileNav = document.querySelector(".site-header-nav.d-none.bg-gray-light")
    const categories = []
    window.categoryMap.forEach((k, v) => {
        categories.push(v)
    })
    categories.sort()
    categories.forEach(
        category => {
            const attrs = {
                "className": "menu-item",
                "href": "javascript:void(0)",
                "innerHTML": category
            }
            nav.appendChild(createNode("a", attrs))
            attrs["className"] = "d-block py-2 px-3 border-top text-gray-dark"
            mobileNav.appendChild(createNode("a", attrs))
        }
    )

    const navs = document.querySelectorAll(".menu-item")
    const mnavs = document.querySelectorAll(".d-block.py-2.px-3.border-top.text-gray-dark")
    const siteHeader = document.querySelector('.site-header')
    const btns = document.querySelector('#pagebtn')
    const listener = event => {
        const category = event.target.innerHTML
        window.currentArticles = categoryMap.has(category) ? categoryMap.get(category) : []
        initPageInfo(0)
        btns.hidden = true
        disableBtn()
        showViews()
    }

    let selectedNav = navs[0]
    navs.forEach(nav => {
        nav.addEventListener('click', event => {
            selectedNav.classList.remove("selected")
            event.target.classList.add("selected")
            selectedNav = event.target
            listener(event)
        })
    })

    mnavs.forEach(nav => {
        nav.addEventListener('click', event => {
            siteHeader.classList.toggle('open')
            listener(event)
        })
    })
}

function switchPage(isNext) {
    currentPage = window.pageInfo.currentPage
    lastPage = window.pageInfo.lastPage
    if (isNext && (currentPage < lastPage)) {
        currentPage++
    } else if (!isNext && (currentPage > 0)) {
        currentPage--
    }
    initPageInfo(currentPage)
    showViews()
}

function listenEvents() {
    const toggle = document.querySelector('.site-header-toggle')
    const siteHeader = document.querySelector('.site-header')
    toggle.addEventListener('click', () => {
        siteHeader.classList.toggle('open')
        toggle.setAttribute('aria-expanded', !toggle.getAttribute('aria-expanded'))
    })
    // 翻页
    const prev = document.querySelector('#prev')
    const next = document.querySelector('#next')
    const btns = document.querySelector('#pagebtn')
    prev.addEventListener('click', () => {
        if (prev.classList.contains("disabled")) {
            return
        }
        btns.hidden = true
        switchPage(false)
        disableBtn()
    })
    next.addEventListener('click', () => {
        if (next.classList.contains("disabled")) {
            return
        }
        btns.hidden = true
        switchPage(true)
        disableBtn()
    })

}

function disableBtn() {
    const prev = document.querySelector('#prev')
    const next = document.querySelector('#next')
    if (window.pageInfo.currentPage == 0) {
        prev.classList.add("disabled")
    } else {
        prev.classList.remove("disabled")
    }
    if (window.pageInfo.currentPage == window.pageInfo.lastPage) {
        next.classList.add("disabled")
    } else {
        next.classList.remove("disabled")
    }

}

function main() {
    const content = document.querySelector("#content")
    fetch('config.json')
        .then(response => {
            return response.json()
        })
        .then(config => {
            parseConfig(config)
            initPageInfo(0)
            initCategories()

            showViews()
        }).then(c => {
            disableBtn()
            listenEvents()
        })

}

main()