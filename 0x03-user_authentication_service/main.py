#!/usr/bin/env python3
"""
Module for E2E integration tests
"""
from requests import get, put, post, delete

def create_user(email: str, password: str) -> None:
    """ Tests user creation
    """
    # Successfully creating a new user
    req = post("http://0.0.0.0:5000/users",
               data={'email': email, 'password': password})
    resp = req.json()
    assert resp == {'email': email, 'message': 'user created'}
    assert req.status_code == 200

    # Attempt to create user with existing email
    req = post("http://0.0.0.0:5000/users",
               data={'email': email, 'password': password})
    resp = req.json()
    assert resp == {'message': 'email already registered'}
    assert req.status_code == 400

def attempt_login_with_incorrect_password(email: str, password: str) -> None:
    """ Incorrect password login test
    """
    req = post("http://0.0.0.0:5000/sessions",
               data={'email': email, 'password': password})
    assert req.status_code == 401
    assert req.cookies.get("session_id") is None

def authenticate_user(email: str, password: str) -> str:
    """ User login test and session ID retrieval
        Return:
            - session_id
    """
    req = post("http://0.0.0.0:5000/sessions",
               data={'email': email, 'password': password})
    resp = req.json()
    session_id = req.cookies.get("session_id")
    assert req.status_code == 200
    assert resp == {'email': email, 'message': 'logged in'}
    assert session_id is not None
    return session_id

def test_profile_access_unauthenticated() -> None:
    """ Test access to user profile when not logged in
    """
    req = get("http://0.0.0.0:5000/profile")
    assert req.status_code == 403

def test_profile_access_authenticated(session_id: str) -> None:
    """ Test access to user profile when logged in
    """
    req = get("http://0.0.0.0:5000/profile",
              cookies={"session_id": session_id})
    resp = req.json()
    assert req.status_code == 200
    assert resp == {'email': EMAIL}

def terminate_session(session_id: str) -> None:
    """ User logout test
    """
    req = delete("http://0.0.0.0:5000/sessions",
                 cookies={"session_id": session_id},
                 allow_redirects=True)
    resp = req.json()
    history = req.history
    assert req.status_code == 200
    assert len(history) == 1
    assert history[0].status_code == 302
    assert resp == {'message': 'Bienvenue'}

def obtain_reset_password_token(email: str) -> str:
    """ Get reset token test
        Return:
            - reset token
    """
    req = post("http://0.0.0.0:5000/reset_password",
               data={"email": email})
    resp = req.json()
    reset_token = resp.get("reset_token")
    assert req.status_code == 200
    assert type(reset_token) is str
    return reset_token

def change_password(email: str, reset_token: str, new_password: str) -> None:
    """ Password update test
    """
    req = put("http://0.0.0.0:5000/reset_password",
              data={"email": email, "new_password": new_password, "reset_token": reset_token})
    resp = req.json()
    assert req.status_code == 200
    assert resp == {'email': email, 'message': 'Password updated'}

EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"

if __name__ == "__main__":

    create_user(EMAIL, PASSWD)
    attempt_login_with_incorrect_password(EMAIL, NEW_PASSWD)
    test_profile_access_unauthenticated()
    session_id = authenticate_user(EMAIL, PASSWD)
    test_profile_access_authenticated(session_id)
    terminate_session(session_id)
    reset_token = obtain_reset_password_token(EMAIL)
    change_password(EMAIL, reset_token, NEW_PASSWD)
    authenticate_user(EMAIL, NEW_PASSWD)
