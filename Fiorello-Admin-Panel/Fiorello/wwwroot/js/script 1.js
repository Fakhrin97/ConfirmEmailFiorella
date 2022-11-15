let loadMoreBtn = document.getElementById("load-more")
let productList = document.getElementById("prduct-list")
let skip = 4

if (loadMoreBtn) {
    loadMoreBtn.addEventListener("click", function () {
        fetch('product/partial?skip=' + skip, {
            method: 'POST'
        })
            .then((response) => response.text())
            .then((data) => {
                productList.innerHTML += data;
                skip += 4;
                let productCount = document.getElementById("prduct-count").value;
                if (skip >= productCount)
                    loadMoreBtn.remove();
            });
    })
}

let searchProduct = document.getElementById("input-search")

searchProduct.addEventListener("keyup", function () {

    let text = this.value
    let productList = document.querySelector("#product-list")

    fetch('home/SearchProducts?searchPrdouctName=' + text)
        .then((response) => response.text())
        .then((data) => {
            productList.innerHTML = data
        });
})

let addToBasket = document.querySelectorAll("#add-to-cart")
if (addToBasket) { 
addToBasket.forEach(cartBtn => {
    cartBtn.addEventListener("mousedown", (ev) => {
        var parentElement = ev.target.parentElement.parentElement.children[0].value
        fetch('home/AddToBasket?id=' + parentElement, {
            method: 'POST'
        })            
    })
})
}





