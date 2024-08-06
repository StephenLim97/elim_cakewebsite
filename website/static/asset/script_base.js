let profileDropdownList = document.querySelector(".profile-dropdown-list");
let btn = document.querySelector(".profile-dropdown-btn");

let classList = profileDropdownList.classList;

const toggle = () => classList.toggle("active");

window.addEventListener("click", function (e) {
  if (!btn.contains(e.target)) classList.remove("active");
});

function showSidebar(){
  const sidebar = document.querySelector('.sidebar')
  sidebar.style.display='flex'

}
function hideSidebar(){
  const sidebar = document.querySelector('.sidebar')
  sidebar.style.display='none'

}