function login () {

  var data = new FormData(document.getElementById("login"));
 
  fetch("/lin", { method:"POST", body:data })
  .then((res) => { return res.text(); })
  .then((txt) => {
  if (txt=="ok!") { location.href = '/frontend' }
    else { alert(txt); }
  })
  .catch((err) => {
    alert("Server issue - " + err.message);
    console.error(err); //måske ikke expose
  });
  return false;
}
