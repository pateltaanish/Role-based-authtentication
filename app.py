import os, json, hmac, hashlib
from pathlib import Path
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session, flash
from functools import wraps

# =========================
# App & config
# =========================
BASE = Path(__file__).resolve().parent
DATA = BASE / "data" / "users.json"

load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY", "dev-key-change-me")

app = Flask(__name__)
app.secret_key = SECRET_KEY

# Data helpers
def load_db():
    if not DATA.exists():
        DATA.parent.mkdir(parents=True, exist_ok=True)
        with DATA.open("w", encoding="utf-8") as f:
            json.dump({}, f, indent=2)
    with DATA.open(encoding="utf-8") as f:
        return json.load(f)

def save_db(db):
    with DATA.open("w", encoding="utf-8") as f:
        json.dump(db, f, indent=2)

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def get_record(db, username):
    """
    Supports:
      new flat schema: db[username] -> {"password_hash": "...", "role": "..."}
      legacy schema:   db["users"][username] -> {"pwd": "$argon2...", "role": "..."}
    """
    if isinstance(db, dict) and username in db and isinstance(db[username], dict):
        return db[username], "new"
    if isinstance(db.get("users"), dict) and username in db["users"]:
        return db["users"][username], "old"
    return None, None

ROLES = ["Library Administrator", "Librarian", "Library Member"]

ROLE_PERMS = {
    "Library Administrator": {
        "manage_users",
        "books:add", "books:delete",
        "borrow", "return",
        "catalog:search",
    },
    "Librarian": {
        "books:add", "books:delete",
        "catalog:search",
    },
    "Library Member": {
        "borrow", "return",
        "catalog:search",
    },
}

def can(user, perm: str) -> bool:
    if not user:
        return False
    return perm in ROLE_PERMS.get(user.get("role"), set())

def requires_perm(perm: str):
    def wrap(fn):
        @wraps(fn)
        def inner(*args, **kwargs):
            user = session.get("user")
            if not can(user, perm):
                flash("Not authorized for this action.", "danger")
                return redirect(url_for("login"))
            return fn(*args, **kwargs)
        return inner
    return wrap

# Admin user-management helpers
def add_user_record(username: str, password: str, role: str):
    db = load_db()
    if not username or not password:
        return False, "Username and password are required."
    if role not in ROLES:
        return False, "Invalid role."
    if username in db:
        return False, "User already exists."
    db[username] = {"password_hash": sha256_hex(password), "role": role}
    save_db(db)
    return True, None

def remove_user_record(username: str, expected_role: str):
    db = load_db()
    rec = db.get(username)
    if not rec:
        return False, "User not found."
    if rec.get("role") != expected_role:
        return False, f"User is not a {expected_role}."
    del db[username]
    save_db(db)
    return True, None


@app.route("/")
def home():
    user = session.get("user")
    return render_template("home.html", user=user)

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "")

        db = load_db()
        rec, kind = get_record(db, u)

        if not rec:
            flash("User not found.", "warning")
            return render_template("login.html")

        ok = False
        role = rec.get("role", "Unknown")

        if kind == "new" and "password_hash" in rec:
            calc = sha256_hex(p)
            ok = (len(calc) == len(rec["password_hash"])) and hmac.compare_digest(calc, rec["password_hash"])
        elif kind == "old" and "pwd" in rec:
            # back-compat for legacy Argon2 records (if any)
            try:
                from argon2 import PasswordHasher
                ph = PasswordHasher()
                ph.verify(rec["pwd"], p)
                ok = True
            except Exception:
                ok = False

        if ok:
            session["user"] = {"username": u, "role": role}
            flash(f"Welcome, {u} ({role}).", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password.", "danger")

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

# Provision: user creation and login
@app.route("/provision", methods=["GET","POST"])
def provision():
    """
    Exactly 3 fields: username, password, role (select).
    - If username exists: verify SHA-256(password) AND selected role match stored record → log in.
    - If username does not exist: create it with SHA-256(password) and selected role.
    """
    roles = ROLES
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "")
        r = request.form.get("role", "")

        if not u or not p or r not in roles:
            flash("Username, password, and a valid role are required.", "danger")
            return render_template("provision.html", roles=roles)

        db = load_db()
        if u in db:
            rec = db[u]
            if "password_hash" not in rec or "role" not in rec:
                flash("Existing record is missing required fields.", "danger")
                return render_template("provision.html", roles=roles)

            calc = sha256_hex(p)
            if hmac.compare_digest(calc, rec["password_hash"]) and rec["role"] == r:
                session["user"] = {"username": u, "role": r}
                flash(f"Welcome back, {u} ({r}).", "success")
                return redirect(url_for("dashboard"))
            else:
                flash("Existing user: password or role does not match the record.", "danger")
                return render_template("provision.html", roles=roles)

        # new user → create
        db[u] = {"password_hash": sha256_hex(p), "role": r}
        save_db(db)
        flash(f"Provisioned user '{u}' as {r}. You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("provision.html", roles=roles)

# Dashboard: main user landing page
@app.route("/dashboard")
def dashboard():
    user = session.get("user")
    if not user:
        flash("Please log in to view the dashboard.", "warning")
        return redirect(url_for("login"))
    allowed = ROLE_PERMS.get(user["role"], set())
    return render_template("dashboard.html", user=user, allowed=allowed)


# Admin: Manage Users & sub-actions (REAL forms)
@app.route("/admin/users")
@requires_perm("manage_users")
def admin_users():
    return render_template("manage_users.html")

@app.route("/admin/users/add-librarian", methods=["GET","POST"])
@requires_perm("manage_users")
def add_librarian():
    if request.method == "POST":
        u = request.form.get("username","").strip()
        p = request.form.get("password","")
        ok, err = add_user_record(u, p, "Librarian")
        if ok:
            flash(f"{u} has been added as Librarian.", "success")
            return redirect(url_for("admin_users"))
        else:
            flash(err, "danger")
    return render_template("user_add.html", title="Add Librarian", role_label="Librarian")

@app.route("/admin/users/remove-librarian", methods=["GET","POST"])
@requires_perm("manage_users")
def remove_librarian():
    if request.method == "POST":
        u = request.form.get("username","").strip()
        ok, err = remove_user_record(u, "Librarian")
        if ok:
            flash(f"{u} has been removed.", "success")
            return redirect(url_for("admin_users"))
        else:
            flash(err, "danger")
    return render_template("user_remove.html", title="Remove Librarian", role_label="Librarian")

@app.route("/admin/users/add-member", methods=["GET","POST"])
@requires_perm("manage_users")
def add_member():
    if request.method == "POST":
        u = request.form.get("username","").strip()
        p = request.form.get("password","")
        ok, err = add_user_record(u, p, "Library Member")
        if ok:
            flash(f"{u} has been added as Library Member.", "success")
            return redirect(url_for("admin_users"))
        else:
            flash(err, "danger")
    return render_template("user_add.html", title="Add Member", role_label="Library Member")

@app.route("/admin/users/remove-member", methods=["GET","POST"])
@requires_perm("manage_users")
def remove_member():
    if request.method == "POST":
        u = request.form.get("username","").strip()
        ok, err = remove_user_record(u, "Library Member")
        if ok:
            flash(f"{u} has been removed.", "success")
            return redirect(url_for("admin_users"))
        else:
            flash(err, "danger")
    return render_template("user_remove.html", title="Remove Member", role_label="Library Member")

# Books (Admin + Librarian) — placeholders
@app.route("/books/add")
@requires_perm("books:add")
def books_add():
    return render_template(
        "action.html",
        title="Add Books to Catalog",
        description="Placeholder: form to add books."
    )

@app.route("/books/delete")
@requires_perm("books:delete")
def books_delete():
    return render_template(
        "action.html",
        title="Delete Books from Catalog",
        description="Placeholder: form to delete books."
    )


# Borrow / Return (Admin + Member) — placeholders

@app.route("/borrow")
@requires_perm("borrow")
def borrow_book():
    return render_template(
        "action.html",
        title="Borrow Books",
        description="Placeholder: borrow flow."
    )

@app.route("/return")
@requires_perm("return")
def return_book():
    return render_template(
        "action.html",
        title="Return Books",
        description="Placeholder: return flow."
    )

# Catalog search (All roles) — placeholder
@app.route("/catalog/search")
@requires_perm("catalog:search")
def catalog_search():
    return render_template(
        "action.html",
        title="Search Library Catalog",
        description="Placeholder: search the catalog."
    )


if __name__ == "__main__":
    app.run(debug=True)
