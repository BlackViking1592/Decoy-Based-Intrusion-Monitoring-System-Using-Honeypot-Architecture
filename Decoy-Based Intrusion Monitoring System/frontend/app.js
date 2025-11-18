const api = "http://localhost:5000";

async function registerUser() {
  const body = {
    name: document.getElementById('name').value,
    dob: document.getElementById('dob').value,
    gender: document.getElementById('gender').value,
    email: document.getElementById('email').value,
    password: document.getElementById('password').value,
    confirm: document.getElementById('confirm').value
  };
  const res = await fetch(api + "/auth/register", {
    method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify(body)
  });
  alert(await res.text());
}

async function login() {
  const body = {
    email: document.getElementById('email').value,
    password: document.getElementById('password').value
  };
  const res = await fetch(api + "/auth/login", {
    method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify(body)
  });
  const data = await res.json();
  alert(JSON.stringify(data));
}

async function loadIntrusions() {
  const key = document.getElementById('adminkey').value;
  const res = await fetch(api + "/admin/intrusions", {
    headers: {"x-admin-key": key}
  });
  const data = await res.json();
  document.getElementById('intrusions').innerText = JSON.stringify(data, null, 2);
}