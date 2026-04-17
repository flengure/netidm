// This file will contain js helpers to have some interactivity on forms that we can't achieve with pure html.
function rehook_string_list_removers() {
    const buttons = document.getElementsByClassName("netidm-remove-list-entry");
    for (let i = 0; i < buttons.length; i++) {
        const button = buttons.item(i)
        if (button.getAttribute("netidm_hooked") !== null) continue

        button.addEventListener("click", (e) => {
            // Expected html nesting: div.email-entry > div.input-group > button.netidm-remove-list-entry
            let li = button.parentElement?.parentElement;
            if (li && li.classList.contains("email-entry")) {
                li.remove();
            }
        })
        button.setAttribute("netidm_hooked", "")
    }
}

window.onload = function () {
    rehook_string_list_removers();
    document.body.addEventListener("addEmailSwapped", () => {
        rehook_string_list_removers();
    })
};

