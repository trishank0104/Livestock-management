

"""
Flask backend for AgriMed Tracker (Supabase-backed)

Usage:
  - Put your Supabase URL and SERVICE_ROLE key in .env (SUPABASE_URL, SUPABASE_SERVICE_KEY)
  - Frontend obtains an access_token via Supabase Auth (Google sign-in) and POSTs it to /auth/verify
  - Server verifies token with Supabase Auth, returns profile info and attaches user to requests
  - Use endpoints under /farmer, /vet, /admin as per roles

Note: This uses the Supabase PostgREST endpoints (REST) via HTTP requests.
"""

import os
import json
from functools import wraps
from datetime import datetime, timedelta, date
from typing import Optional, Dict, Any, List
import traceback
import requests
import supabase
from flask import Blueprint, Flask, redirect, request, jsonify, g
import google.generativeai as genai
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
# Optional scheduler for background alerts
from apscheduler.schedulers.background import BackgroundScheduler

from supabase import create_client, Client
from flask import Flask, render_template

app = Flask(__name__, template_folder="templates", static_folder="static")
# 🏠 Route for Home Page

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/ping")
def ping():
    return {"status": "ok", "message": "Flask is working ✅"}

# 👨‍🌾 Farmer Dashboard
@app.route("/farmer")
def farmer_dashboard():
    return render_template("farmer_dashboard.html")

# 🐾 Vet Dashboard
@app.route("/vet")
def vet_dashboard():
    return render_template("vet_dashboard.html")

# 👨‍💼 Admin Dashboard
@app.route("/admin")
def admin_dashboard():
    return render_template("admin_dashboard.html")



load_dotenv()

SUPABASE_URL = os.environ.get("SUPABASE_URL")  # https://<project>.supabase.co
SUPABASE_REST = SUPABASE_URL.rstrip("/") + "/rest/v1"
SUPABASE_AUTH_URL = SUPABASE_URL.rstrip("/") + "/auth/v1"
SERVICE_KEY = os.environ.get("SUPABASE_SERVICE_KEY")  # service_role
ANON_KEY = os.environ.get("SUPABASE_ANON_KEY")  # optional
OPENAI_KEY = os.environ.get("OPENAI_API_KEY")


HEADERS_SERVICE = {
    "apikey": SERVICE_KEY,
    "Authorization": f"Bearer {SERVICE_KEY}",
    "Content-Type": "application/json",
}

# For verifying frontend token
HEADERS_ANON = {
    "apikey": ANON_KEY or SERVICE_KEY,
    "Content-Type": "application/json",
}


genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))

ai_bp = Blueprint("ai", __name__)

@ai_bp.route("/chatbot", methods=["POST"])
def chatbot():
    try:
        user_message = request.json.get("message")
        if not user_message:
            return jsonify({"error": "Message is required"}), 400

        model = genai.GenerativeModel("gemini-1.5-flash")
        response = model.generate_content(
            f"Act as an experienced veterinarian and food safety expert. "
            f"Answer briefly: {user_message}"
        )

        return jsonify({"reply": response.text})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ------------------------
# Helper: Supabase REST calls
# ------------------------
def supabase_get(table: str, params: Optional[Dict[str, str]] = None, select: str = "*") -> Dict[str, Any]:
    """
    Generic GET from Supabase PostgREST.
    params: dict of query params (PostgREST style), e.g. {"user_id": "eq.<uuid>"}
    select: select string, default "*"
    """
    url = f"{SUPABASE_REST}/{table}"
    q = {"select": select}
    if params:
        q.update(params)
    resp = requests.get(url, headers=HEADERS_SERVICE, params=q)
    resp.raise_for_status()
    return resp.json()


def supabase_insert(table: str, payload: Any, returning: str = "*") -> Any:
    url = f"{SUPABASE_REST}/{table}"
    headers = HEADERS_SERVICE.copy()
    headers["Prefer"] = "return=representation"
    params = {"select": returning}
    r = requests.post(url, headers=headers, json=payload, params=params)
    r.raise_for_status()
    return r.json()


def supabase_update(table: str, match: Dict[str, Any], payload: Dict[str, Any], returning: str = "*") -> Any:
    url = f"{SUPABASE_REST}/{table}"
    headers = HEADERS_SERVICE.copy()
    headers["Prefer"] = "return=representation"
    # Build match query string like ?id=eq.<val>&...
    params = {"select": returning}
    params.update({k: f"eq.{v}" for k, v in match.items()})
    r = requests.patch(url, headers=headers, json=payload, params=params)
    r.raise_for_status()
    return r.json()


def supabase_delete(table: str, match: Dict[str, Any], returning: str = "*") -> Any:
    url = f"{SUPABASE_REST}/{table}"
    headers = HEADERS_SERVICE.copy()
    headers["Prefer"] = "return=representation"
    params = {"select": returning}
    params.update({k: f"eq.{v}" for k, v in match.items()})
    r = requests.delete(url, headers=headers, params=params)
    r.raise_for_status()
    return r.json()

app.register_blueprint(ai_bp, url_prefix='/ai')

# ... (after your supabase_delete function)

def supabase_auth_signup(email: str, password: str) -> Optional[Dict[str, Any]]:
    """
    Signs up a new user in Supabase Auth.
    """
    url = f"{SUPABASE_AUTH_URL}/signup"
    payload = {"email": email, "password": password}
    r = requests.post(url, headers=HEADERS_ANON, json=payload)
    
    # --- THIS IS THE CORRECTED LOGIC ---
    if r.status_code in (200, 201): 
        return r.json()
    else:
        app.logger.error(f"Supabase signup failed with status {r.status_code}: {r.text}")
        return None
    # --- END OF CORRECTION ---


def supabase_storage_upload(bucket_name: str, file_path: str, file) -> str:
    """
    Uploads a file to a Supabase Storage bucket.
    """
    url = f"{SUPABASE_URL.rstrip('/')}/storage/v1/object/{bucket_name}/{file_path}"
    
    # Supabase storage requires a specific content type for the file
    content_type = file.mimetype
    headers = HEADERS_SERVICE.copy()
    headers['Content-Type'] = content_type
    
    r = requests.post(url, headers=headers, data=file.read())
    r.raise_for_status()
    
    # Return the public URL of the uploaded file
    public_url = f"{SUPABASE_URL.rstrip('/')}/storage/v1/object/public/{bucket_name}/{file_path}"
    return public_url

# ------------------------
# Auth & user profile lookup
# ------------------------
def get_auth_user_from_token(access_token: str) -> Optional[dict]:
    """
    Call Supabase Auth endpoint to validate access_token.
    Returns auth user JSON on success, else None.
    """
    if not access_token:
        return None
    url = f"{SUPABASE_AUTH_URL}/user"
    headers = {"Authorization": f"Bearer {access_token}", "apikey": ANON_KEY or SERVICE_KEY}
    r = requests.get(url, headers=headers)
    if r.status_code != 200:
        return None
    return r.json()


def audit_log(table_name: str, entity_id: Optional[str], action: str, previous: Optional[dict], new: Optional[dict], user_id: Optional[str]):
    """
    Insert into audit_logs table for traceability.
    """
    payload = {
        "table_name": table_name,
        "entity_id": entity_id,
        "action": action,
        "previous_data": previous,
        "new_data": new,
        "user_id": user_id,
    }
    try:
        supabase_insert("audit_logs", [payload])
    except Exception as e:
        app.logger.error("Failed to write audit log: %s", e)


def fetch_profile(auth_user_id: str) -> Optional[dict]:
    """
    Look up 'profiles' table by auth user id. If not found, attempt to fetch 'users' by email.
    Returns profile dict or None.
    """
    try:
        rows = supabase_get("profiles", params={"user_id": f"eq.{auth_user_id}"})
        if rows:
            return rows[0]
    except Exception as e:
        app.logger.info("profiles lookup failed: %s", e)
    return None


def fetch_public_user_by_auth(auth_user_id: str) -> Optional[dict]:
    """If you maintain public.users keyed by same UUID, fetch it; else fallback profile."""
    try:
        rows = supabase_get("users", params={"user_id": f"eq.{auth_user_id}"})
        if rows:
            return rows[0]
    except Exception as e:
        app.logger.info("public.users lookup failed: %s", e)
    return None

# Add this to your app.py for Google complete profile
# REPLACE the existing complete_google_profile function in app.py with this one.

@app.route("/auth/complete-google-profile", methods=["POST"])
def complete_google_profile():
    """Complete profile for Google signup users."""
    try:
        # --- Form Data Extraction ---
        user_id = request.form.get("user_id")
        role = request.form.get("role")
        name = request.form.get("name")
        email = request.form.get("email")
        farm_name = request.form.get("farm_name")
        id_proof_file = request.files.get('id_proof_file')

        # --- Stricter Validation (THE FIX) ---
        # We now check for required fields based on the selected role.
        if not all([user_id, role, name, email]):
            return jsonify({"success": False, "message": "User ID, role, name, and email are required."}), 400
        
        if role == "vet" and not id_proof_file:
            return jsonify({"success": False, "message": "ID proof document was not received by the server."}), 400
        
        if role == "farmer" and not farm_name:
            return jsonify({"success": False, "message": "Farm name is required for farmer registration."}), 400

        # --- Database Insertion ---
        user_payload = {
            "user_id": user_id, "email": email, "name": name, "role": role,
            "status": "pending_approval" if role == "vet" else "active"
        }
        new_user = supabase_insert("users", [user_payload])[0]

        # --- Role-Specific Logic (File Upload) ---
        if role == "vet":
            # This block now only runs if id_proof_file is guaranteed to exist.
            filename = secure_filename(id_proof_file.filename)
            file_path = f"vet-proofs/{user_id}/{filename}"
            public_url = supabase_storage_upload("vet-documents", file_path, id_proof_file)
            
            # Update the user record with the URL of the uploaded document.
            supabase_update("users", {"user_id": user_id}, {"id_proof_url": public_url})

        elif role == "farmer":
            farm_payload = {"farmer_id": user_id, "name": farm_name}
            supabase_insert("farms", [farm_payload])

        audit_log("users", user_id, "google_signup_complete", None, new_user, user_id)
        
        return jsonify({"success": True, "message": "Profile completed successfully!", "user": new_user}), 201
        
    except Exception as e:
        app.logger.error(f"Google profile completion failed: {e}")
        return jsonify({"success": False, "message": str(e)}), 500
# ------------------------
# Decorator: verify_auth
# ------------------------


def verify_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        token = None
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1]
        elif request.json and "access_token" in request.json:
            token = request.json.get("access_token")

        if not token:
            return jsonify({"success": False, "message": "Authorization token required"}), 401

        auth_user = get_auth_user_from_token(token)
        if not auth_user:
            return jsonify({"success": False, "message": "Invalid or expired token"}), 401

        # Attach minimal user info to g
        g.auth_user = auth_user  # full auth user from Supabase
        # Try to get profile
        profile = fetch_profile(auth_user.get("id"))
        public_user = fetch_public_user_by_auth(auth_user.get("id"))

        # Preferred source: profiles table; else public.users fallback
        if profile:
            g.user = {
                "id": auth_user.get("id"),
                "email": auth_user.get("email"),
                "role": profile.get("role"),
                "farm_id": profile.get("farm_id"),
                "full_name": profile.get("full_name"),
            }
        elif public_user:
            g.user = {
                "id": public_user.get("user_id"),
                "email": public_user.get("email"),
                "role": public_user.get("role"),
                "phone": public_user.get("phone"),
            }
        else:
            # Unknown user - still allow but role None
            g.user = {"id": auth_user.get("id"), "email": auth_user.get("email"), "role": None}

        return fn(*args, **kwargs)
    return wrapper

# ... (after your /auth/verify endpoint)


# =====================================================================
# New Registration & Approval Workflow
# =====================================================================
@app.route("/auth/signup/farmer", methods=["POST"])
def signup_farmer():
    """Handles farmer signup and creates their first farm."""
    body = request.json or {}
    email = body.get("email")
    password = body.get("password")
    name = body.get("name")
    farm_name = body.get("farm_name") # <-- ADDED

    if not all([email, password, name, farm_name]): # <-- MODIFIED
        return jsonify({"success": False, "message": "Email, password, name, and farm name are required"}), 400

    auth_user = supabase_auth_signup(email, password)
    if not auth_user or "user" not in auth_user:
        return jsonify({"success": False, "message": "Could not create user. The email may be in use."}), 409

    auth_user_id = auth_user["user"]["id"]

    try:
        user_payload = {"user_id": auth_user_id, "email": email, "name": name, "role": "farmer", "status": "active"}
        new_user = supabase_insert("users", [user_payload])[0]

        # --- NEW LOGIC TO CREATE THE FARM ---
        farm_payload = {"farmer_id": auth_user_id, "name": farm_name}
        new_farm = supabase_insert("farms", [farm_payload])[0]
        # --- END OF NEW LOGIC ---

        audit_log("users", auth_user_id, "signup", None, new_user, auth_user_id)
        audit_log("farms", new_farm.get("id"), "create_on_signup", None, new_farm, auth_user_id) # <-- ADDED

        return jsonify({"success": True, "message": "Farmer registered successfully!", "user": new_user}), 201
    except Exception as e:
        app.logger.error(f"Farmer signup failed: {e}")
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/auth/signup/vet", methods=["POST"])
def signup_vet():
    """ Public endpoint for a vet to sign up. Account is pending approval. """
    try:
        # This is a multipart form, not JSON
        email = request.form.get("email")
        password = request.form.get("password")
        name = request.form.get("name")
        id_proof_file = request.files.get('id_proof_file')

        if not email or not password or not name or not id_proof_file:
            return jsonify({"success": False, "message": "email, password, name, and id_proof_file are required"}), 400

        # 1. Create user in auth.users
        auth_user = supabase_auth_signup(email, password)
        if not auth_user or not auth_user.get("user"):
            return jsonify({"success": False, "message": "Could not create authentication user. The email might be in use."}), 409
        
        auth_user_id = auth_user["user"]["id"]
        
        # 2. Upload ID proof to Supabase Storage
        filename = secure_filename(id_proof_file.filename)
        file_path = f"vet-proofs/{auth_user_id}/{filename}"
        # Make sure you have a bucket named 'vet-documents' in your Supabase Storage
        file_url = supabase_storage_upload("vet-documents", file_path, id_proof_file)

        # 3. Create user in public.users with pending status
        user_payload = {
            "user_id": auth_user_id,
            "email": email,
            "name": name,
            "role": "vet",
            "status": "pending_approval", # Vets must be approved
            "id_proof_url": file_url
        }
        new_user = supabase_insert("users", [user_payload])[0]
        audit_log("users", auth_user_id, "signup", None, new_user, auth_user_id)

        return jsonify({"success": True, "message": "Vet registration successful. Your account is pending approval."}), 201

    except Exception as e:
        app.logger.exception(e)
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/official/vets/pending-approval", methods=["GET"])
@verify_auth
def official_get_pending_vets():
    """ Endpoint for officials to see vets awaiting approval. """
    if not g.user or g.user.get("role") not in ("official", "admin"):
        return jsonify({"success": False, "message": "Official role required"}), 403
    
    try:
        pending_vets = supabase_get("users", params={"role": "eq.vet", "status": "eq.pending_approval"})
        return jsonify({"success": True, "pending_vets": pending_vets})
    except Exception as e:
        app.logger.exception(e)
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/official/vets/<string:vet_id>/approve", methods=["POST"])
@verify_auth
def official_approve_vet(vet_id):
    """ Endpoint for an official to approve a vet's registration. """
    if not g.user or g.user.get("role") not in ("official", "admin"):
        return jsonify({"success": False, "message": "Official role required"}), 403
    try:
        prev = supabase_get("users", params={"user_id": f"eq.{vet_id}"})
        if not prev:
            return jsonify({"success": False, "message": "Vet not found."}), 404
            
        updated = supabase_update("users", {"user_id": vet_id}, {"status": "active"})[0]
        audit_log("users", vet_id, "approve", prev[0], updated, g.user["id"])
        
        # You could add an email notification to the vet here
        
        return jsonify({"success": True, "message": f"Vet {vet_id} has been approved."})
    except Exception as e:
        app.logger.exception(e)
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/official/vets/<string:vet_id>/reject", methods=["POST"])
@verify_auth
def official_reject_vet(vet_id):
    """ Endpoint for an official to reject a vet's registration. """
    if not g.user or g.user.get("role") not in ("official", "admin"):
        return jsonify({"success": False, "message": "Official role required"}), 403
    try:
        prev = supabase_get("users", params={"user_id": f"eq.{vet_id}"})
        if not prev:
            return jsonify({"success": False, "message": "Vet not found."}), 404
            
        updated = supabase_update("users", {"user_id": vet_id}, {"status": "rejected"})[0]
        audit_log("users", vet_id, "reject", prev[0], updated, g.user["id"])
        
        return jsonify({"success": True, "message": f"Vet {vet_id} has been rejected."})
    except Exception as e:
        app.logger.exception(e)
        return jsonify({"success": False, "message": str(e)}), 500
# ------------------------
# Auth endpoint (frontend uses this after Google login)
# ------------------------
@app.route("/auth/verify", methods=["POST"])
def auth_verify():
    """Verifies a token and checks if the user has a profile in public.users."""
    body = request.get_json(silent=True) or {}
    token = body.get("access_token") or request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        return jsonify({"success": False, "message": "access_token required"}), 400

    auth_user = get_auth_user_from_token(token)
    if not auth_user:
        return jsonify({"success": False, "message": "Invalid token"}), 401

    public_user = fetch_public_user_by_auth(auth_user.get("id"))

    response_data = {"auth_user": auth_user}
    if public_user:
        response_data["public_user"] = public_user
    else:
        # This NEW flag tells the frontend to show the "Complete Profile" form
        response_data["is_new_user"] = True

    return jsonify({"success": True, "data": response_data})

# =====================================================================
# Farmer endpoints (REVISED AND EXPANDED SECTION)
# =====================================================================

##-- NEW --##
# Requirement: A farmer can have multiple farms. 
@app.route("/farmer/farms", methods=["POST"])
@verify_auth
def farmer_create_farm():
    """ Allows a logged-in farmer to create an additional farm. """
    try:
        body = request.json or {}
        if not body.get("name"):
            return jsonify({"success": False, "message": "Farm name is required"}), 400
        
        payload = {
            "farmer_id": g.user["id"],
            "name": body.get("name"),
            "location": body.get("location"), # Assuming location is a JSON object
            "description": body.get("description")
        }
        res = supabase_insert("farms", [payload])
        audit_log("farms", res[0].get("id"), "create", None, res[0], g.user["id"])
        return jsonify({"success": True, "farm": res[0]}), 201

    except Exception as e:
        app.logger.exception(e)
        return jsonify({"success": False, "message": str(e)}), 500


# Requirement: View Livestock List. 
@app.route("/farmer/animals", methods=["GET"])
@verify_auth
def farmer_get_animals():
    try:
        uid = g.user["id"]
        # ##-- ENHANCEMENT --##: Added filtering capability
        params = {"owner_id": f"eq.{uid}"}
        status_filter = request.args.get("status")
        if status_filter:
            params["status"] = f"eq.{status_filter}"

        animals = supabase_get("animals", params=params)
        return jsonify({"success": True, "animals": animals})
    except Exception as e:
        app.logger.exception(e)
        return jsonify({"success": False, "message": str(e)}), 500

##-- ENHANCEMENT --##
# Requirement: View Animal Details (comprehensive profile). 
@app.route("/farmer/animals/<string:tag_id>", methods=["GET"])
@verify_auth
def farmer_get_animal(tag_id):
    """ Fetches a single animal's complete history. """
    try:
        uid = g.user["id"]
        rows = supabase_get("animals", params={"tag_id": f"eq.{tag_id}", "owner_id": f"eq.{uid}"})
        if not rows:
            return jsonify({"success": False, "message": "Animal not found or you do not have permission"}), 404
        
        animal_data = rows[0]

        # Aggregate related data for a comprehensive view
        health_logs = supabase_get("health_logs", params={"tag_id": f"eq.{tag_id}"})
        prescriptions = supabase_get("prescriptions", params={"animal_id": f"eq.{tag_id}"})
        
        # ##-- ENHANCEMENT --##: Age calculation logic 
        if animal_data.get("dob"):
            try:
                dob = date.fromisoformat(animal_data["dob"])
                today = date.today()
                age_delta = today - dob
                years = age_delta.days // 365
                months = (age_delta.days % 365) // 30
                animal_data["calculated_age"] = f"{years} years, {months} months"
            except (ValueError, TypeError):
                animal_data["calculated_age"] = "N/A"

        response = {
            "animal": animal_data,
            "health_logs": health_logs,
            "prescriptions": prescriptions
        }
        return jsonify({"success": True, "data": response})
    except Exception as e:
        app.logger.exception(e)
        return jsonify({"success": False, "message": str(e)}), 500

# Requirement: Add animals. 
@app.route("/farmer/animals", methods=["POST"])
@verify_auth
def farmer_create_animal():
    try:
        body = request.json or {}
        tag_id = body.get("tag_id")
        species = body.get("species")
        farm_id = body.get("farm_id")
        if not tag_id or not species or not farm_id:
            return jsonify({"success": False, "message": "tag_id, species, farm_id required"}), 400

        payload = {
            "tag_id": tag_id,
            "owner_id": g.user["id"],
            "species": species,
            "breed": body.get("breed"),
            "dob": body.get("dob"),
            "gender": body.get("gender"),
            "rfid_code": body.get("rfid_code"),
            "farm_id": farm_id,
            "farm_location": body.get("farm_location"),
        }
        res = supabase_insert("animals", [payload])
        audit_log("animals", tag_id, "create", None, res[0], g.user["id"])
        return jsonify({"success": True, "animal": res[0]}), 201
    except Exception as e:
        app.logger.exception(e)
        return jsonify({"success": False, "message": str(e)}), 500

##-- ENHANCEMENT --##
# Requirement: Mark as Sold/Transferred  or Dead.
@app.route("/farmer/animals/<string:tag_id>", methods=["PUT", "PATCH"])
@verify_auth
def farmer_update_animal(tag_id):
    try:
        body = request.json or {}
        uid = g.user["id"]
        
        prev = supabase_get("animals", params={"tag_id": f"eq.{tag_id}", "owner_id": f"eq.{uid}"})
        if not prev:
            return jsonify({"success": False, "message": "Animal not found"}), 404
        
        # ##-- ENHANCEMENT --##: Prevent editing of archived records as per requirement 
        if prev[0].get("status") in ["sold", "dead", "archived"]:
             return jsonify({"success": False, "message": f"Record is read-only. Animal status is '{prev[0].get('status')}'."}), 403

        # These fields are conceptual based on readme; add them to your 'animals' table schema
        # e.g., sold_to (text), sold_date (date), cause_of_death (text)
        updates = {k: v for k, v in {
            "breed": body.get("breed"),
            "dob": body.get("dob"),
            "gender": body.get("gender"),
            "rfid_code": body.get("rfid_code"),
            "farm_location": body.get("farm_location"),
            "status": body.get("status"),
            # "sold_to": body.get("sold_to"), 
            # "cause_of_death": body.get("cause_of_death")
        }.items() if v is not None}

        if not updates:
            return jsonify({"success": False, "message": "No fields to update"}), 400

        updated = supabase_update("animals", {"tag_id": tag_id, "owner_id": uid}, updates)
        audit_log("animals", tag_id, "update", prev[0], updated[0], g.user["id"])
        return jsonify({"success": True, "updated": updated[0]})
    except Exception as e:
        app.logger.exception(e)
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/farmer/animals/<string:tag_id>", methods=["DELETE"])
@verify_auth
def farmer_delete_animal(tag_id):
    try:
        uid = g.user["id"]
        prev = supabase_get("animals", params={"tag_id": f"eq.{tag_id}", "owner_id": f"eq.{uid}"})
        if not prev:
            return jsonify({"success": False, "message": "Animal not found"}), 404
        deleted = supabase_delete("animals", {"tag_id": tag_id, "owner_id": uid})
        audit_log("animals", tag_id, "delete", prev[0], None, g.user["id"])
        return jsonify({"success": True, "deleted": deleted[0]})
    except Exception as e:
        app.logger.exception(e)
        return jsonify({"success": False, "message": str(e)}), 500

# ------------------------
# Farmer: feed batches (medicated feed)
# ------------------------
# Requirement: Add Medicated Feed Batch. 
@app.route("/farmer/feed_batches", methods=["POST"])
@verify_auth
def farmer_create_feed_batch():
    try:
        body = request.json or {}
        farm_id = body.get("farm_id")
        antimicrobial = body.get("antimicrobial")
        if not farm_id or not antimicrobial:
            return jsonify({"success": False, "message": "farm_id and antimicrobial required"}), 400
        payload = {
            "farm_id": farm_id,
            "antimicrobial": antimicrobial,
            "concentration": body.get("concentration"),
            "batch_number": body.get("batch_number"),
            "start_date": body.get("start_date"),
            "end_date": body.get("end_date"),
            "withdrawal_days": body.get("withdrawal_days"),
            "status": body.get("status") or "in_use"
        }
        res = supabase_insert("feed_batches", [payload])
        audit_log("feed_batches", res[0].get("id"), "create", None, res[0], g.user["id"])
        return jsonify({"success": True, "feed_batch": res[0]}), 201
    except Exception as e:
        app.logger.exception(e)
        return jsonify({"success": False, "message": str(e)}), 500

# Requirement: View Active & Past Batches. 
@app.route("/farmer/feed_batches", methods=["GET"])
@verify_auth
def farmer_list_feed_batches():
    try:
        farm_id = request.args.get("farm_id")
        if not farm_id:
            return jsonify({"success": False, "message": "farm_id required"}), 400
        rows = supabase_get("feed_batches", params={"farm_id": f"eq.{farm_id}"})
        return jsonify({"success": True, "feed_batches": rows})
    except Exception as e:
        app.logger.exception(e)
        return jsonify({"success": False, "message": str(e)}), 500

##-- NEW --##
# Requirement: Update Batch Status to "Finished"  or "Archived".
@app.route("/farmer/feed_batches/<string:batch_id>", methods=["PATCH"])
@verify_auth
def farmer_update_feed_batch(batch_id):
    try:
        body = request.json or {}
        status = body.get("status")
        if not status or status not in ["in_use", "finished", "archived"]:
            return jsonify({"success": False, "message": "A valid status ('in_use', 'finished', 'archived') is required"}), 400
        
        # Security check: Ensure the batch belongs to one of the farmer's farms.
        farms = supabase_get("farms", params={"farmer_id": f"eq.{g.user['id']}"}, select="id")
        farmer_farm_ids = [f['id'] for f in farms]
        
        prev = supabase_get("feed_batches", params={"id": f"eq.{batch_id}"})
        if not prev or prev[0].get("farm_id") not in farmer_farm_ids:
            return jsonify({"success": False, "message": "Feed batch not found or permission denied"}), 404

        updates = {"status": status}
        updated = supabase_update("feed_batches", {"id": batch_id}, updates)
        audit_log("feed_batches", batch_id, "update", prev[0], updated[0], g.user["id"])
        return jsonify({"success": True, "updated": updated[0]})
    except Exception as e:
        app.logger.exception(e)
        return jsonify({"success": False, "message": str(e)}), 500

# ------------------------
# Farmer: health logs
# ------------------------
# Requirement: Update animal health records. 
@app.route("/farmer/health_log", methods=["POST"])
@verify_auth
def farmer_health_log():
    try:
        body = request.json or {}
        tag_id = body.get("tag_id")
        if not tag_id:
            return jsonify({"success": False, "message": "tag_id required"}), 400
        payload = {
            "tag_id": tag_id,
            "farmer_id": g.user["id"],
            "temperature": body.get("temperature"),
            "weight": body.get("weight"),
            "symptoms": body.get("symptoms"),
            "notes": body.get("notes"),
            "status": body.get("status") or "normal",
            "is_error": body.get("is_error", False),
            "error_reason": body.get("error_reason")
        }
        res = supabase_insert("health_logs", [payload])
        audit_log("health_logs", res[0].get("id"), "create", None, res[0], g.user["id"])
        return jsonify({"success": True, "log": res[0]}), 201
    except Exception as e:
        app.logger.exception(e)
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/farmer/health_logs", methods=["GET"])
@verify_auth
def farmer_get_health_logs():
    try:
        tag_id = request.args.get("tag_id")
        farm_id = request.args.get("farm_id")
        if tag_id:
            rows = supabase_get("health_logs", params={"tag_id": f"eq.{tag_id}"})
        elif farm_id:
            animals = supabase_get("animals", params={"farm_id": f"eq.{farm_id}"}, select="tag_id")
            tags = [a["tag_id"] for a in animals] if animals else []
            if not tags:
                return jsonify({"success": True, "logs": []})
            tags_filter = ",".join([f"'{t}'" for t in tags])
            url = f"{SUPABASE_REST}/health_logs?tag_id=in.({tags_filter})"
            r = requests.get(url, headers=HEADERS_SERVICE)
            r.raise_for_status()
            rows = r.json()
        else:
            rows = supabase_get("health_logs", params={"farmer_id": f"eq.{g.user['id']}"})
        return jsonify({"success": True, "logs": rows})
    except Exception as e:
        app.logger.exception(e)
        return jsonify({"success": False, "message": str(e)}), 500

##-- NEW --##
# Requirement: Add Notes to Record  or Mark as Entry Error.
@app.route("/farmer/health_logs/<string:log_id>", methods=["PATCH"])
@verify_auth
def farmer_update_health_log(log_id):
    """ Allows a farmer to either append notes or mark a log as an error. """
    try:
        body = request.json or {}
        uid = g.user["id"]
        
        prev = supabase_get("health_logs", params={"id": f"eq.{log_id}", "farmer_id": f"eq.{uid}"})
        if not prev:
            return jsonify({"success": False, "message": "Health log not found or permission denied"}), 404
        
        updates = {}
        # Logic to append notes 
        if "notes" in body:
            existing_notes = prev[0].get("notes") or ""
            new_note = f"\n[Update @ {datetime.utcnow().isoformat()}]: {body['notes']}"
            updates["notes"] = existing_notes + new_note
        
        # Logic to mark as error 
        if body.get("is_error") is True:
            if not body.get("error_reason"):
                return jsonify({"success": False, "message": "An error_reason is mandatory when marking an entry as an error."}), 400
            updates["is_error"] = True
            updates["error_reason"] = body.get("error_reason")

        if not updates:
            return jsonify({"success": False, "message": "No valid fields to update (provide 'notes' or 'is_error')."}), 400

        updated = supabase_update("health_logs", {"id": log_id}, updates)
        audit_log("health_logs", log_id, "update", prev[0], updated[0], uid)
        return jsonify({"success": True, "updated": updated[0]})
    except Exception as e:
        app.logger.exception(e)
        return jsonify({"success": False, "message": str(e)}), 500

##-- NEW --##
# Requirement: Farmer can see the prescription given by vet. 
@app.route("/farmer/prescriptions", methods=["GET"])
@verify_auth
def farmer_list_prescriptions():
    """ Fetches all prescriptions for the logged-in farmer. """
    try:
        uid = g.user["id"]
        params = {"farmer_id": f"eq.{uid}"}
        
        # Allow optional filtering by animal
        animal_id = request.args.get("animal_id")
        if animal_id:
            params["animal_id"] = f"eq.{animal_id}"
            
        rows = supabase_get("prescriptions", params=params, select="*")
        return jsonify({"success": True, "prescriptions": rows})
    except Exception as e:
        app.logger.exception(e)
        return jsonify({"success": False, "message": str(e)}), 500

# =====================================================================
# Vet endpoints
# =====================================================================
# =====================================================================
# Vet endpoints
# =====================================================================

def is_vet():
    """ Helper function to check for vet or admin role. """
    return g.user and g.user.get("role") in ("vet", "admin")

# [cite_start]Requirement: 2. View Client List [cite: 19] [cite_start]& 3. View Client Profile [cite: 20]
@app.route("/vet/clients", methods=["GET"])
@verify_auth
def vet_get_clients():
    """
    Gets a list of all farmers/farms associated with the vet.
    A farm is considered a client if the vet has issued a prescription or logged a consultation for them.
    """
    if not is_vet():
        return jsonify({"success": False, "message": "Vet role required"}), 403
    try:
        vet_id = g.user["id"]
        # Get unique farm IDs from both prescriptions and consultations
        presc_farms = supabase_get("prescriptions", params={"vet_id": f"eq.{vet_id}"}, select="farm_id")
        consult_farms = supabase_get("consultations", params={"vet_id": f"eq.{vet_id}"}, select="farm_id")
        
        farm_ids = set()
        if presc_farms:
            farm_ids.update(p['farm_id'] for p in presc_farms if p.get('farm_id'))
        if consult_farms:
            farm_ids.update(c['farm_id'] for c in consult_farms if c.get('farm_id'))

        if not farm_ids:
            return jsonify({"success": True, "clients": []})

        # Fetch farm details for the unique farm IDs
        farm_ids_filter = ",".join([f"'{fid}'" for fid in farm_ids])
        url = f"{SUPABASE_REST}/farms?id=in.({farm_ids_filter})&select=*,farmer:farmer_id(*)"
        r = requests.get(url, headers=HEADERS_SERVICE)
        r.raise_for_status()
        clients = r.json()
        
        return jsonify({"success": True, "clients": clients})
    except Exception as e:
        app.logger.exception(e)
        return jsonify({"success": False, "message": str(e)}), 500

# [cite_start]Requirement: 1. Onboard New Farmer/Farm [cite: 18]
@app.route("/vet/clients", methods=["POST"])
@verify_auth
def vet_onboard_client():
    """
    Onboards a new farmer and creates their first farm.
    NOTE: This creates a record in public.users, not auth.users. User needs to sign up separately.
    This endpoint establishes the relationship in the public schema.
    """
    if not is_vet():
        return jsonify({"success": False, "message": "Vet role required"}), 403
    try:
        body = request.json or {}
        user_data = body.get("user")
        farm_data = body.get("farm")

        if not user_data or not farm_data or not user_data.get("email") or not farm_data.get("name"):
            return jsonify({"success": False, "message": "User and farm data (including user email and farm name) are required"}), 400

        # Create the user profile
        user_payload = {
            "name": user_data.get("name"),
            "email": user_data.get("email"),
            "phone": user_data.get("phone"),
            "location": user_data.get("location"),
            "role": "farmer"
        }
        new_user = supabase_insert("users", [user_payload])[0]
        audit_log("users", new_user.get("user_id"), "create", None, new_user, g.user["id"])
        
        # Create the farm and link it to the new user
        farm_payload = {
            "name": farm_data.get("name"),
            "location": farm_data.get("location"),
            "description": farm_data.get("description"),
            "farmer_id": new_user.get("user_id")
        }
        new_farm = supabase_insert("farms", [farm_payload])[0]
        audit_log("farms", new_farm.get("id"), "create", None, new_farm, g.user["id"])
        
        return jsonify({"success": True, "user": new_user, "farm": new_farm}), 201

    except Exception as e:
        app.logger.exception(e)
        # Basic error handling for duplicate email
        if "duplicate key value violates unique constraint" in str(e):
            return jsonify({"success": False, "message": "A user with this email already exists."}), 409
        return jsonify({"success": False, "message": str(e)}), 500

# [cite_start]Requirement: 4. Edit Client Details [cite: 21] [cite_start]& 5. De-register Client [cite: 22]
@app.route("/vet/farms/<string:farm_id>", methods=["PATCH"])
@verify_auth
def vet_update_farm_details(farm_id):
    """ Allows a vet to update farm details or mark a farm as inactive. """
    if not is_vet():
        return jsonify({"success": False, "message": "Vet role required"}), 403
    try:
        body = request.json or {}
        # Simple check for authorization can be added here (e.g., vet must have a prior prescription for this farm)
        
        prev = supabase_get("farms", params={"id": f"eq.{farm_id}"})
        if not prev:
            return jsonify({"success": False, "message": "Farm not found"}), 404
        
        updates = {k: v for k, v in {
            "name": body.get("name"),
            "location": body.get("location"),
            "description": body.get("description"),
            "status": body.get("status") # e.g., 'inactive' to de-register
        }.items() if v is not None}

        if not updates:
            return jsonify({"success": False, "message": "No fields to update provided."}), 400

        updated = supabase_update("farms", {"id": farm_id}, updates)[0]
        audit_log("farms", farm_id, "update", prev[0], updated, g.user["id"])

        return jsonify({"success": True, "updated_farm": updated})
    except Exception as e:
        app.logger.exception(e)
        return jsonify({"success": False, "message": str(e)}), 500


# [cite_start]Requirement: 6. Issue New Prescription [cite: 24]
# This route already exists in the provided code, so we ensure it's complete.
@app.route("/vet/prescriptions", methods=["POST"])
@verify_auth
def vet_create_prescription():
    if not is_vet():
        return jsonify({"success": False, "message": "Vet role required"}), 403
    try:
        body = request.json or {}
        animal_id = body.get("animal_id")
        drug = body.get("drug")
        if not animal_id or not drug:
            return jsonify({"success": False, "message": "animal_id and drug are required"}), 400
        
        # Fetch farmer_id and farm_id from the animal record for data integrity
        animal_record = supabase_get("animals", params={"tag_id": f"eq.{animal_id}"})
        if not animal_record:
            return jsonify({"success": False, "message": "Animal not found"}), 404

        payload = {
            "vet_id": g.user["id"],
            "farmer_id": animal_record[0].get("owner_id"),
            "farm_id": animal_record[0].get("farm_id"),
            "animal_id": animal_id,
            "drug": drug,
            "dose": body.get("dose"),
            "route": body.get("route"),
            "start_date": body.get("start_date") or date.today().isoformat(),
            "duration_days": body.get("duration_days"),
            "status": "active",
            "reason": body.get("reason"),
            "notes": body.get("notes"),
            "withdrawal_days": body.get("withdrawal_days")
        }
        res = supabase_insert("prescriptions", [payload])[0]
        audit_log("prescriptions", res.get("id"), "create", None, res, g.user["id"])
        return jsonify({"success": True, "prescription": res}), 201
    except Exception as e:
        app.logger.exception(e)
        return jsonify({"success": False, "message": str(e)}), 500

# [cite_start]Requirement: 7. View Prescription History [cite: 25] (Enhanced with filtering)
@app.route("/vet/prescriptions", methods=["GET"])
@verify_auth
def vet_list_prescriptions():
    if not is_vet():
        return jsonify({"success": False, "message": "Vet role required"}), 403
    try:
        params = {"vet_id": f"eq.{g.user['id']}"}
        # Add filtering based on query parameters
        if request.args.get("farm_id"): params["farm_id"] = f"eq.{request.args.get('farm_id')}"
        if request.args.get("animal_id"): params["animal_id"] = f"eq.{request.args.get('animal_id')}"
        if request.args.get("drug"): params["drug"] = f"ilike.%{request.args.get('drug')}%" # case-insensitive search
        if request.args.get("date"): params["start_date"] = f"eq.{request.args.get('date')}"
            
        rows = supabase_get("prescriptions", params=params, select="*")
        return jsonify({"success": True, "prescriptions": rows})
    except Exception as e:
        app.logger.exception(e)
        return jsonify({"success": False, "message": str(e)}), 500

# [cite_start]Requirement: 8. Amend Prescription [cite: 26] [cite_start]& 9. Cancel Prescription [cite: 27]
@app.route("/vet/prescriptions/<string:presc_id>/cancel", methods=["POST"])
@verify_auth
def vet_cancel_prescription(presc_id):
    
    if not is_vet():
        return jsonify({"success": False, "message": "Vet role required"}), 403
    try:
        body = request.json or {}
        reason = body.get("reason")
        if not reason:
            return jsonify({"success": False, "message": "A reason for cancellation is mandatory."}), 400

        prev = supabase_get("prescriptions", params={"id": f"eq.{presc_id}", "vet_id": f"eq.{g.user['id']}"})
        if not prev:
            return jsonify({"success": False, "message": "Prescription not found or you are not the author."}), 404

        # Append cancellation reason to notes for audit trail
        existing_notes = prev[0].get("notes") or ""
        updated_notes = existing_notes + f"\n[Cancelled @ {datetime.utcnow().isoformat()}]: {reason}"
        
        updates = {"status": "cancelled", "notes": updated_notes}
        updated = supabase_update("prescriptions", {"id": presc_id}, updates)[0]
        audit_log("prescriptions", presc_id, "cancel", prev[0], updated, g.user["id"])

        return jsonify({"success": True, "cancelled_prescription": updated})
    except Exception as e:
        app.logger.exception(e)
        return jsonify({"success": False, "message": str(e)}), 500

# [cite_start]Requirement: 10. Log Farm Visit [cite: 29]
@app.route("/vet/consultations", methods=["POST"])
@verify_auth
def vet_create_consultation():
    if not is_vet():
        return jsonify({"success": False, "message": "Vet role required"}), 403
    try:
        body = request.json or {}
        if not body.get("farm_id") or not body.get("diagnosis"):
            return jsonify({"success": False, "message": "farm_id and diagnosis are required"}), 400
        
        payload = {
            "vet_id": g.user["id"],
            "farm_id": body.get("farm_id"),
            "diagnosis": body.get("diagnosis"),
            "clinical_notes": body.get("clinical_notes"),
            "visit_date": body.get("visit_date") or date.today().isoformat(),
            "linked_prescriptions": body.get("linked_prescriptions") # Expects an array of prescription UUIDs
        }
        res = supabase_insert("consultations", [payload])[0]
        audit_log("consultations", res.get("id"), "create", None, res, g.user["id"])
        return jsonify({"success": True, "consultation": res}), 201
    except Exception as e:
        app.logger.exception(e)
        return jsonify({"success": False, "message": str(e)}), 500

# [cite_start]Requirement: 11. View Consultation History [cite: 31]
@app.route("/vet/consultations", methods=["GET"])
@verify_auth
def vet_get_consultations():
    if not is_vet():
        return jsonify({"success": False, "message": "Vet role required"}), 403
    try:
        # Vet can see all their consultations, filterable by farm
        params = {"vet_id": f"eq.{g.user['id']}"}
        farm_id = request.args.get("farm_id")
        if farm_id:
            params["farm_id"] = f"eq.{farm_id}"
        
        rows = supabase_get("consultations", params=params)
        return jsonify({"success": True, "consultations": rows})
    except Exception as e:
        app.logger.exception(e)
        return jsonify({"success": False, "message": str(e)}), 500

# [cite_start]Requirement: 12. Add Follow-up Notes to consultation [cite: 32]
@app.route("/vet/consultations/<string:consult_id>", methods=["PATCH"])
@verify_auth
def vet_update_consultation(consult_id):
    if not is_vet():
        return jsonify({"success": False, "message": "Vet role required"}), 403
    try:
        body = request.json or {}
        notes_to_add = body.get("notes")
        if not notes_to_add:
            return jsonify({"success": False, "message": "Follow-up notes are required."}), 400

        prev = supabase_get("consultations", params={"id": f"eq.{consult_id}", "vet_id": f"eq.{g.user['id']}"})
        if not prev:
            return jsonify({"success": False, "message": "Consultation not found or you are not the author."}), 404

        existing_notes = prev[0].get("clinical_notes") or ""
        updated_notes = existing_notes + f"\n[Follow-up @ {datetime.utcnow().isoformat()}]: {notes_to_add}"
        
        updates = {"clinical_notes": updated_notes}
        updated = supabase_update("consultations", {"id": consult_id}, updates)[0]
        audit_log("consultations", consult_id, "update", prev[0], updated, g.user["id"])
        
        return jsonify({"success": True, "updated_consultation": updated})
    except Exception as e:
        app.logger.exception(e)
        return jsonify({"success": False, "message": str(e)}), 500
# =====================================================================
# Admin endpoints
# =====================================================================
# =====================================================================
# Official endpoints
# =====================================================================

def is_official():
    """ Helper function to check for official or admin role. """
    return g.user and g.user.get("role") in ("official", "admin")

# --- Data Monitoring & Analysis ---

# Requirement: Query Aggregated Data [cite: 36]
@app.route("/official/data/query", methods=["GET"])
@verify_auth
def official_query_data():
    """
    A powerful endpoint for officials to query aggregated and anonymized data.
    NOTE: For complex joins and performance, creating a PostgreSQL function (RPC)
    in Supabase is highly recommended over direct table queries.
    """
    if not is_official():
        return jsonify({"success": False, "message": "Official role required"}), 403
    try:
        # Example filters - a real implementation would have more
        params = {}
        if request.args.get("species"): params["species"] = f"eq.{request.args.get('species')}"
        if request.args.get("drug"): params["drug"] = f"ilike.%{request.args.get('drug')}%"
        if request.args.get("reason"): params["reason"] = f"eq.{request.args.get('reason')}"
        
        # Anonymized data selection: exclude PII like farmer_id, vet_id
        # This selects prescription details along with anonymized animal and farm info
        select_query = "drug,dose,reason,start_date,duration_days,animal:animal_id(species,breed),farm:farm_id(location)"
        
        # This query runs against the 'prescriptions' table and joins related data
        results = supabase_get("prescriptions", params=params, select=select_query)
        
        return jsonify({"success": True, "data": results, "count": len(results)})
    except Exception as e:
        app.logger.exception(e)
        return jsonify({"success": False, "message": str(e)}), 500

# Requirement: Access Audit Logs [cite: 37]
@app.route("/official/audit-logs", methods=["GET"])
@verify_auth
def official_get_audit_logs():
    """ Allows officials to view immutable system audit logs for data integrity checks. """
    if not is_official():
        return jsonify({"success": False, "message": "Official role required"}), 403
    try:
        params = {}
        # Add filtering for more targeted auditing
        if request.args.get("table_name"): params["table_name"] = f"eq.{request.args.get('table_name')}"
        if request.args.get("user_id"): params["user_id"] = f"eq.{request.args.get('user_id')}"
        if request.args.get("action"): params["action"] = f"eq.{request.args.get('action')}"
        
        # You can also add date range filters here
        
        logs = supabase_get("audit_logs", params=params)
        return jsonify({"success": True, "audit_logs": logs})
    except Exception as e:
        app.logger.exception(e)
        return jsonify({"success": False, "message": str(e)}), 500

# --- Report Management ---

# Requirement: Generate Report [cite: 38]
@app.route("/official/reports", methods=["POST"])
@verify_auth
def official_create_report():
    """
    Creates a new report document based on a specific data query.
    The actual file generation (CSV/PDF) and upload to storage is stubbed.
    """
    if not is_official():
        return jsonify({"success": False, "message": "Official role required"}), 403
    try:
        body = request.json or {}
        title = body.get("title")
        query_params = body.get("query_params") # The filters for the report
        if not title or not query_params:
            return jsonify({"success": False, "message": "title and query_params are required"}), 400

        # --- Placeholder for complex logic ---
        # 1. Run a data query using query_params (similar to official_query_data).
        # 2. Format the data into a CSV or PDF file using a library like pandas or ReportLab.
        # 3. Upload the generated file to Supabase Storage.
        # 4. Get the public URL of the uploaded file.
        file_url_from_storage = f"https://<project>.supabase.co/storage/v1/object/public/reports/report_{date.today().isoformat()}.pdf"
        # --- End of placeholder ---

        payload = {
            "created_by": g.user["id"],
            "title": title,
            "file_url": file_url_from_storage,
        }
        res = supabase_insert("reports", [payload])[0]
        audit_log("reports", res.get("id"), "create", None, res, g.user["id"])
        
        return jsonify({"success": True, "report": res}), 201
    except Exception as e:
        app.logger.exception(e)
        return jsonify({"success": False, "message": str(e)}), 500

# Requirement: View/Download Generated Reports [cite: 39]
@app.route("/official/reports", methods=["GET"])
@verify_auth
def official_get_reports():
    """ Retrieves a list of all previously generated reports. """
    if not is_official():
        return jsonify({"success": False, "message": "Official role required"}), 403
    try:
        reports = supabase_get("reports")
        return jsonify({"success": True, "reports": reports})
    except Exception as e:
        app.logger.exception(e)
        return jsonify({"success": False, "message": str(e)}), 500

# Requirement: Rename/Annotate Report [cite: 40]
@app.route("/official/reports/<string:report_id>", methods=["PATCH"])
@verify_auth
def official_update_report(report_id):
    """ Allows an official to update the title of a generated report. """
    if not is_official():
        return jsonify({"success": False, "message": "Official role required"}), 403
    try:
        body = request.json or {}
        title = body.get("title")
        if not title:
            return jsonify({"success": False, "message": "A new title is required"}), 400

        prev = supabase_get("reports", params={"id": f"eq.{report_id}"})
        if not prev:
            return jsonify({"success": False, "message": "Report not found"}), 404
        
        updated = supabase_update("reports", {"id": report_id}, {"title": title})[0]
        audit_log("reports", report_id, "update", prev[0], updated, g.user["id"])
        
        return jsonify({"success": True, "updated_report": updated})
    except Exception as e:
        app.logger.exception(e)
        return jsonify({"success": False, "message": str(e)}), 500

# Requirement: Delete a Generated Report [cite: 41]
@app.route("/official/reports/<string:report_id>", methods=["DELETE"])
@verify_auth
def official_delete_report(report_id):
    """ Deletes a generated report record. Does not affect source data. [cite: 42] """
    if not is_official():
        return jsonify({"success": False, "message": "Official role required"}), 403
    try:
        prev = supabase_get("reports", params={"id": f"eq.{report_id}"})
        if not prev:
            return jsonify({"success": False, "message": "Report not found"}), 404

        # NOTE: Add logic here to delete the actual file from Supabase Storage.
        
        deleted = supabase_delete("reports", {"id": report_id})[0]
        audit_log("reports", report_id, "delete", prev[0], None, g.user["id"])
        
        return jsonify({"success": True, "deleted_report": deleted})
    except Exception as e:
        app.logger.exception(e)
        return jsonify({"success": False, "message": str(e)}), 500


# --- Alert Rule Management ---

# Requirement: Define New Alert Rule [cite: 42]
@app.route("/official/alert-rules", methods=["POST"])
@verify_auth
def official_create_alert_rule():
    """ Creates a new system-wide alert rule. """
    if not is_official():
        return jsonify({"success": False, "message": "Official role required"}), 403
    try:
        body = request.json or {}
        if not body.get("name") or not body.get("condition") or not body.get("severity"):
            return jsonify({"success": False, "message": "name, condition (JSON), and severity are required"}), 400

        payload = {
            "name": body.get("name"),
            "condition": body.get("condition"),
            "severity": body.get("severity")
        }
        res = supabase_insert("alert_rules", [payload])[0]
        audit_log("alert_rules", res.get("id"), "create", None, res, g.user["id"])
        return jsonify({"success": True, "alert_rule": res}), 201
    except Exception as e:
        app.logger.exception(e)
        return jsonify({"success": False, "message": str(e)}), 500

# Requirement: View Active Rules [cite: 43]
@app.route("/official/alert-rules", methods=["GET"])
@verify_auth
def official_get_alert_rules():
    """ Retrieves all configured alert rules. """
    if not is_official():
        return jsonify({"success": False, "message": "Official role required"}), 403
    try:
        rules = supabase_get("alert_rules")
        return jsonify({"success": True, "alert_rules": rules})
    except Exception as e:
        app.logger.exception(e)
        return jsonify({"success": False, "message": str(e)}), 500

# Requirement: Modify Alert Rule [cite: 44]
@app.route("/official/alert-rules/<string:rule_id>", methods=["PATCH"])
@verify_auth
def official_update_alert_rule(rule_id):
    """ Modifies the parameters of an existing alert rule. """
    if not is_official():
        return jsonify({"success": False, "message": "Official role required"}), 403
    try:
        body = request.json or {}
        prev = supabase_get("alert_rules", params={"id": f"eq.{rule_id}"})
        if not prev:
            return jsonify({"success": False, "message": "Alert rule not found"}), 404
        
        updates = {k: v for k, v in {
            "name": body.get("name"),
            "condition": body.get("condition"),
            "severity": body.get("severity")
        }.items() if v is not None}

        if not updates:
            return jsonify({"success": False, "message": "No fields to update provided."}), 400

        updated = supabase_update("alert_rules", {"id": rule_id}, updates)[0]
        audit_log("alert_rules", rule_id, "update", prev[0], updated, g.user["id"])
        return jsonify({"success": True, "updated_rule": updated})
    except Exception as e:
        app.logger.exception(e)
        return jsonify({"success": False, "message": str(e)}), 500

# Requirement: Deactivate Alert Rule [cite: 45]
@app.route("/official/alert-rules/<string:rule_id>", methods=["DELETE"])
@verify_auth
def official_delete_alert_rule(rule_id):
    """
    Deletes an alert rule. To 'deactivate', consider adding an 'is_active'
    boolean column to the alert_rules table and using the PATCH method.
    """
    if not is_official():
        return jsonify({"success": False, "message": "Official role required"}), 403
    try:
        prev = supabase_get("alert_rules", params={"id": f"eq.{rule_id}"})
        if not prev:
            return jsonify({"success": False, "message": "Alert rule not found"}), 404

        deleted = supabase_delete("alert_rules", {"id": rule_id})[0]
        audit_log("alert_rules", rule_id, "delete", prev[0], None, g.user["id"])
        return jsonify({"success": True, "deleted_rule": deleted})
    except Exception as e:
        app.logger.exception(e)
        return jsonify({"success": False, "message": str(e)}), 500
    



# =====================================================================
# Admin endpoints
# =====================================================================
def is_admin():
    """ Helper function to check for admin role. """
    return g.user and g.user.get("role") == "admin"


@app.route("/admin/users", methods=["GET", "POST"])
@verify_auth
def admin_users():
    if not is_admin():
        return jsonify({"success": False, "message": "Admin role required"}), 403
    
    if request.method == "GET":
        """ Fetches all users in the system. """
        try:
            users = supabase_get("users")
            return jsonify({"success": True, "users": users})
        except Exception as e:
            app.logger.exception(e)
            return jsonify({"success": False, "message": str(e)}), 500
    
    else: # POST method
        """ Creates a new user with authentication, typically for officials. """
        try:
            body = request.json or {}
            email = body.get("email")
            password = body.get("password")
            role = body.get("role")
            
            if not email or not password or not role:
                return jsonify({"success": False, "message": "email, password, and role are required."}), 400

            # 1. Create the auth user
            auth_user = supabase_auth_signup(email, password)
            if not auth_user or not auth_user.get("user"):
                return jsonify({"success": False, "message": "Could not create authentication user. The email might be in use."}), 409
            
            auth_user_id = auth_user["user"]["id"]
            
            # 2. Create the public user profile
            user_payload = {
                "user_id": auth_user_id,
                "email": email,
                "name": body.get("name"),
                "role": role,
                "phone": body.get("phone"),
                "location": body.get("location"),
                "status": "active" # Users created by admin are active by default
            }
            new_user = supabase_insert("users", [user_payload])[0]
            audit_log("users", auth_user_id, "admin_create", None, new_user, g.user["id"])

            return jsonify({"success": True, "message": "User created successfully by admin.", "user": new_user}), 201
        except Exception as e:
            app.logger.exception(e)
            return jsonify({"success": False, "message": str(e)}), 500


@app.route("/admin/users/<string:user_id>", methods=["PUT", "PATCH", "DELETE"])
@verify_auth
def admin_modify_user(user_id):
    if not is_admin():
        return jsonify({"success": False, "message": "Admin role required"}), 403

    if request.method in ["PUT", "PATCH"]:
        """ Updates a user's details in the public.users table. """
        try:
            body = request.json or {}
            prev = supabase_get("users", params={"user_id": f"eq.{user_id}"})
            if not prev:
                return jsonify({"success": False, "message": "User not found"}), 404

            updates = {k: v for k, v in {
                "name": body.get("name"),
                "role": body.get("role"),
                "phone": body.get("phone"),
                "location": body.get("location"),
                "status": body.get("status")
            }.items() if v is not None}

            if not updates:
                return jsonify({"success": False, "message": "No fields to update."}), 400

            updated = supabase_update("users", {"user_id": user_id}, updates)[0]
            audit_log("users", user_id, "admin_update", prev[0], updated, g.user["id"])
            return jsonify({"success": True, "updated_user": updated})

        except Exception as e:
            app.logger.exception(e)
            return jsonify({"success": False, "message": str(e)}), 500

    if request.method == "DELETE":
        """ Deletes a user from public.users. NOTE: This does not delete the auth.users entry. """
        try:
            prev = supabase_get("users", params={"user_id": f"eq.{user_id}"})
            if not prev:
                return jsonify({"success": False, "message": "User not found"}), 404
            
            deleted = supabase_delete("users", {"user_id": user_id})[0]
            audit_log("users", user_id, "admin_delete", prev[0], None, g.user["id"])
            
            # For full cleanup, you would also need to call the Supabase Admin API to delete the user from auth.users
            # This requires the supabase-py library and admin credentials.
            
            return jsonify({"success": True, "deleted_user": deleted})
        except Exception as e:
            app.logger.exception(e)
            return jsonify({"success": False, "message": str(e)}), 500



# =====================================================================
# Shared endpoints (e.g., RFID scan)
# =====================================================================
@app.route("/scan/<string:rfid_or_tag>", methods=["GET"])
@verify_auth
def scan_rfid(rfid_or_tag):
    """
    Accepts either RFID code or tag_id. Returns animal info, latest prescriptions,
    feed batch impact (if farm has active feed meds), and aggregated withdrawal status.
    """
    try:
        rows = supabase_get("animals", params={"rfid_code": f"eq.{rfid_or_tag}"})
        if not rows:
            rows = supabase_get("animals", params={"tag_id": f"eq.{rfid_or_tag}"})
        if not rows:
            return jsonify({"success": False, "message": "Animal not found"}), 404
        animal = rows[0]
        tag_id = animal["tag_id"]
        
        prescs = supabase_get("prescriptions", params={"animal_id": f"eq.{tag_id}"})
        prescs_sorted = sorted(prescs, key=lambda p: p.get("start_date") or p.get("created_at") or "", reverse=True)
        latest_presc = prescs_sorted[0] if prescs_sorted else None

        farm_id = animal.get("farm_id")
        feed_batches = []
        if farm_id:
            feed_batches = supabase_get("feed_batches", params={"farm_id": f"eq.{farm_id}"})
            today = date.today()
            def is_active(batch):
                sd = batch.get("start_date")
                ed = batch.get("end_date")
                if sd and ed:
                    try:
                        sdt = datetime.fromisoformat(sd).date()
                        edt = datetime.fromisoformat(ed).date()
                        return sdt <= today <= edt
                    except Exception:
                        return batch.get("status") == "in_use"
                return batch.get("status") == "in_use"
            feed_batches = [b for b in feed_batches if is_active(b)]
            
        def calc_withdrawal_end_from_presc(p):
            wd = p.get("withdrawal_days") or 0
            sd = p.get("start_date") or p.get("created_at")
            if not sd: return None
            try: sdt = datetime.fromisoformat(str(sd)).date()
            except Exception: sdt = date.fromisoformat(str(sd))
            return sdt + timedelta(days=int(wd))
        
        cand_dates = []
        if latest_presc:
            end = calc_withdrawal_end_from_presc(latest_presc)
            if end: cand_dates.append(end)
        for b in feed_batches:
            wd = b.get("withdrawal_days")
            ed = b.get("end_date")
            if ed and wd:
                try: edt = datetime.fromisoformat(str(ed)).date()
                except Exception: edt = date.fromisoformat(str(ed))
                cand_dates.append(edt + timedelta(days=int(wd)))
        
        withdrawal_end = max(cand_dates) if cand_dates else None
        days_left = (withdrawal_end - date.today()).days if withdrawal_end and withdrawal_end > date.today() else 0
        safe = not withdrawal_end or date.today() >= withdrawal_end
        
        result = {
            "animal": animal,
            "latest_prescription": latest_presc,
            "feed_batches_active": feed_batches,
            "withdrawal_end": withdrawal_end.isoformat() if withdrawal_end else None,
            "days_left": days_left,
            "is_safe_to_sell": safe
        }
        return jsonify({"success": True, "result": result})
    except Exception as e:
        app.logger.exception(e)
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/withdrawal/calc/<string:tag_id>", methods=["GET"])
@verify_auth
def withdrawal_calc(tag_id):
    return scan_rfid(tag_id)


# =====================================================================
# Alerts & AI
# =====================================================================
def generate_alerts_now():
    """ Scans prescriptions & feed_batches to insert alerts for animals currently in withdrawal. """
    try:
        animals = supabase_get("animals")
        created = 0
        for a in animals:
            tag = a["tag_id"]
            # To simulate a request for the scan_rfid logic, we can call it directly with a dummy context
            # This is simpler than duplicating the logic. We will need to mock `g` or adapt.
            # For simplicity, we'll duplicate the core withdrawal calculation logic.
            prescs = supabase_get("prescriptions", params={"animal_id": f"eq.{tag}"})
            prescs_sorted = sorted(prescs, key=lambda p: p.get("start_date") or p.get("created_at") or "", reverse=True)
            latest_presc = prescs_sorted[0] if prescs_sorted else None
            
            farm_id = a.get("farm_id")
            feed_batches = supabase_get("feed_batches", params={"farm_id": f"eq.{farm_id}"}) if farm_id else []
            
            cand_dates = []
            if latest_presc and (latest_presc.get("withdrawal_days") is not None):
                try:
                    sdt = date.fromisoformat(str(latest_presc.get("start_date") or latest_presc.get("created_at")))
                    cand_dates.append(sdt + timedelta(days=int(latest_presc.get("withdrawal_days") or 0)))
                except (TypeError, ValueError): pass
            for b in feed_batches:
                if b.get("end_date") and b.get("withdrawal_days"):
                    try:
                        edt = date.fromisoformat(str(b.get("end_date")))
                        cand_dates.append(edt + timedelta(days=int(b.get("withdrawal_days"))))
                    except (TypeError, ValueError): pass
            
            if not cand_dates: continue
            
            withdrawal_end = max(cand_dates)
            days_left = (withdrawal_end - date.today()).days
            
            if days_left >= 0:
                user_id = a.get("owner_id")
                message = f"Animal {tag} is under withdrawal until {withdrawal_end.isoformat()} ({days_left} days left)."
                payload = {"user_id": user_id, "animal_id": tag, "type": "withdrawal", "message": message, "send_at": datetime.utcnow().isoformat()}
                try:
                    # Optional: check if a similar alert already exists to avoid duplicates
                    res = supabase_insert("alerts", [payload])
                    audit_log("alerts", res[0].get("id"), "create", None, res[0], None)
                    created += 1
                except Exception as e:
                    app.logger.error("Failed to create alert for %s: %s", tag, e)
        return created
    except Exception as e:
        app.logger.exception(e)
        return 0

@app.route("/alerts/generate", methods=["POST"])
@verify_auth
def alerts_generate_endpoint():
    if g.user.get("role") not in ("vet", "admin"):
        return jsonify({"success": False, "message": "vet/admin required to generate alerts"}), 403
    created = generate_alerts_now()
    return jsonify({"success": True, "created_alerts": created})

scheduler = BackgroundScheduler()
 #scheduler.add_job(generate_alerts_now, 'cron', hour=6, minute=0)
# scheduler.start()


@app.route("/ai/chat", methods=["POST"])
@verify_auth
def ai_chat():
    body = request.json or {}
    prompt = body.get("prompt")
    tag_id = body.get("tag_id")
    if not prompt:
        return jsonify({"success": False, "message": "prompt required"}), 400

    context = ""
    if tag_id:
        try:
            rows = supabase_get("animals", params={"tag_id": f"eq.{tag_id}"})
            if rows:
                a = rows[0]
                context += f"Animal {a.get('tag_id')}, species {a.get('species')}, breed {a.get('breed')}, dob {a.get('dob')}.\n"
            prescs = supabase_get("prescriptions", params={"animal_id": f"eq.{tag_id}"})
            if prescs:
                context += "Recent prescriptions:\n"
                for p in prescs[:3]:
                    context += f"- {p.get('drug')} start {p.get('start_date')}\n"
        except Exception as e:
            app.logger.debug("AI context fetch failed: %s", e)

    final_prompt = f"{context}\nUser question: {prompt}\nAnswer succinctly as a helpful vet assistant for a farmer."


    # --- FIXED SECTION ---
    # This now calls the actual Gemini model
    try:
        model = genai.GenerativeModel("gemini-1.5-flash")
        response = model.generate_content(final_prompt)
        response_text = response.text
    except Exception as e:
        app.logger.error(f"Gemini AI call failed: {e}")
        app.logger.error(traceback.format_exc())
        return jsonify({"success": False, "response": "Sorry, the AI service is currently unavailable."}), 500
    # --- END OF FIX ---

    return jsonify({"success": True, "response": response_text})
   
    
load_dotenv()
print("DEBUG: Loaded Google API Key is ->", os.getenv("GOOGLE_API_KEY")) # Add this line
# Supabase Python Client (for easier auth handling)
supabase_client: Client = create_client(SUPABASE_URL, SERVICE_KEY)

def fetch_profile(user_id: str):
    """Fetch user profile from users table."""
    try:
        response = supabase_client.table('users').select('*').eq('user_id', user_id).execute()
        return response.data[0] if response.data else None
    except Exception as e:
        app.logger.error(f"Profile fetch failed: {e}")
        return None

def fetch_public_user_by_auth(user_id: str):
    """Fallback: Fetch public user info."""
    try:
        response = supabase_client.table('users').select('role, status').eq('user_id', user_id).execute()
        return response.data[0] if response.data else None
    except Exception as e:
        app.logger.error(f"Public user fetch failed: {e}")
        return None

@app.route('/auth/callback')
def auth_callback():
    """Handle Supabase OAuth callback (exchanges code for session)."""
    try:
        # Get the auth code from query params
        code = request.args.get('code')
        if not code:
            app.logger.warning("No auth code in callback")
            return redirect('/?error=no_code')

        # Exchange code for session using Supabase client
        result = supabase_client.auth.exchange_code_for_session(code)
        if result.user:
            session = result.session
            user_id = session.user.id
            app.logger.info(f"User {user_id} authenticated via OAuth")

            # Fetch profile and redirect based on status/role
            user_profile = fetch_profile(user_id) or fetch_public_user_by_auth(user_id)
            if user_profile and user_profile.get('status') == 'active':
                role = user_profile.get('role', 'farmer')
                return redirect(f'/{role}')
            else:
                # For new/pending users (e.g., Google signup), redirect to complete profile or login
                return redirect('/?message=pending_approval')
        else:
            app.logger.error(f"OAuth exchange failed: {result.error}")
            return redirect('/?error=auth_failed')
    except Exception as e:
        app.logger.error(f"Auth callback failed: {e}")
        return redirect('/?error=callback_failed')

# Add this new endpoint to your app.py
@app.route("/farmer/farms", methods=["GET"])
@verify_auth
def farmer_get_farms():
    """ Allows a logged-in farmer to get a list of their farms. """
    try:
        # g.user['id'] is available from the @verify_auth decorator
        farmer_id = g.user["id"]
        
        # Query the database for farms owned by this farmer
        farms = supabase_get("farms", params={"farmer_id": f"eq.{farmer_id}"})
        
        return jsonify({"success": True, "farms": farms})
    except Exception as e:
        app.logger.exception(e)
        return jsonify({"success": False, "message": str(e)}), 500
# ------------------------
# Run server
# ------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"Starting Flask server on http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=True)