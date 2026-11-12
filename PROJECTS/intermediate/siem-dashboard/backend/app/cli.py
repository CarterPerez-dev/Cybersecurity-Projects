"""
©AngelaMos | 2026
cli.py

Flask CLI commands for admin account management

Provides the admin CLI group with a create command that either
creates a new admin user or promotes an existing user by username
or email. Registered on the Flask app during startup via register_cli.

Key exports:
  admin_cli - Click command group
  register_cli - attaches admin_cli to the Flask app

Connects to:
  __init__.py - calls register_cli
  core/auth.py - calls hash_password
  models/User.py - calls find_by_username, create_user, set_role
"""

import click
from flask import Flask

from app.core.auth import hash_password
from app.models.User import User, UserRole


@click.group("admin")
def admin_cli() -> None:
    """
    Administrative commands for the SIEM platform
    """


@admin_cli.command("create")
@click.option("--username", required = True, help = "Admin username")
@click.option("--email", required = True, help = "Admin email address")
@click.option(
    "--password",
    prompt = True,
    hide_input = True,
    confirmation_prompt = True,
    help = "Admin password"
)
def create_admin(username: str, email: str, password: str) -> None:
    """
    Create a new admin account or promote an existing user
    """
    existing = User.find_by_username(username)
    if existing is not None:
        if existing.role == UserRole.ADMIN:
            click.echo(f"User '{username}' is already an admin.")
            return
        existing.set_role(UserRole.ADMIN)
        click.echo(f"Promoted existing user '{username}' to admin.")
        return

    existing_email = User.find_by_email(email)
    if existing_email is not None:
        if existing_email.role == UserRole.ADMIN:
            click.echo(f"User with email '{email}' is already an admin.")
            return
        existing_email.set_role(UserRole.ADMIN)
        click.echo(f"Promoted existing user '{existing_email.username}' to admin.")
        return

    hashed = hash_password(password)
    User.create_user(
        username = username,
        email = email,
        password_hash = hashed,
        role = UserRole.ADMIN,
    )
    click.echo(f"Admin account '{username}' created successfully.")


def register_cli(app: Flask) -> None:
    """
    Attach all CLI command groups to the Flask app
    """
    app.cli.add_command(admin_cli)
