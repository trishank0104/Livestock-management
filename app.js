// 🟢 Initialize Supabase
const supabase = window.supabase.createClient(
  "https://YOUR_SUPABASE_PROJECT_URL.supabase.co",
  "YOUR_SUPABASE_ANON_KEY"
);

// 🔑 Email/Password Login
async function loginWithEmail() {
  const email = document.getElementById("email").value;
  const password = document.getElementById("password").value;

  const { data, error } = await supabase.auth.signInWithPassword({ email, password });

  if (error) {
    showError(error.message);
  } else {
    fetchUserRole(data.user.id);
  }
}

// 🔑 Google Auth
async function loginWithGoogle() {
  const { data, error } = await supabase.auth.signInWithOAuth({ provider: "google" });
  if (error) showError(error.message);
}

// Fetch user role from Supabase
async function fetchUserRole(userId) {
  const { data, error } = await supabase
    .from("users")
    .select("role")
    .eq("user_id", userId)
    .single();

  if (error) {
    console.error("Error fetching role:", error.message);
    redirectToDashboard("farmer"); // default fallback
  } else {
    redirectToDashboard(data.role);
  }
}

// Redirect based on role
function redirectToDashboard(role) {
  localStorage.setItem("role", role);
  if (role === "farmer") {
    window.location.href = "farmer_dashboard.html";
  } else if (role === "vet") {
    window.location.href = "vet_dashboard.html";
  } else if (role === "admin") {
    window.location.href = "admin_dashboard.html";
  } else {
    window.location.href = "dashboard.html"; // fallback
  }
}

function showError(message) {
  const errorElem = document.getElementById("error");
  errorElem.textContent = message;
  errorElem.classList.remove("hidden");
}
