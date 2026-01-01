===========================================
Fullstack Template: FastAPI + React + Nginx
===========================================

*Production-ready Docker setup with TypeScript and SCSS*

----

Setup
=====

Option 1: GitHub Template (Recommended)
---------------------------------------

Click the **"Use this template"** button above, or:

.. code-block:: bash

   gh repo create my-project --template CarterPerez-dev/fullstack-template
   cd my-project

Option 2: Clone
---------------

.. code-block:: bash

   git clone https://github.com/CarterPerez-dev/fullstack-template.git my-project
   cd my-project
   rm -rf .git && git init

Prerequisites (Optional but Recommended)
----------------------------------------

Install `just <https://github.com/casey/just>`_ command runner:

.. code-block:: bash

   curl --proto '=https' --tlsv1.2 -sSf https://just.systems/install.sh | bash -s -- --to ~/bin

Then add ``~/bin`` to your PATH if not already.

Installation
------------

.. code-block:: bash

   chmod +x setup.sh
   ./setup.sh

Or if you have just:

.. code-block:: bash

   just setup

This will:

- Copy ``.env.example`` → ``.env`` with generated ``SECRET_KEY``
- Move template files (LICENSE, CONTRIBUTING, etc.) to root
- Install backend dependencies (uv sync)
- Install frontend dependencies (pnpm install)

Next Steps
----------

1. Edit ``.env`` with your configuration
2. Start development: ``just dev-up``
3. After creating models: ``just migration-local "initial"`` then ``just migrate-local head``

Run ``just`` to see all available commands.

----

Documentation
=============

Comprehensive guides for understanding and customizing this template:

Backend
-------

- `Backend Architecture <https://github.com/CarterPerez-dev/fullstack-template/blob/documentation/docs/wiki/backend.md>`_

  Complete backend architecture including FastAPI setup, security patterns (JWT + Argon2id), database models, repository pattern, services, API endpoints, testing, and production deployment.

Frontend
--------

- `Frontend Architecture <https://github.com/CarterPerez-dev/fullstack-template/blob/documentation/docs/wiki/frontend.md>`_

  React 19 + TypeScript architecture with TanStack Query, Zustand state management, complete design system (OKLCH colors), API integration patterns, SCSS utilities, and performance optimizations.

Infrastructure
--------------

- `Nginx Configuration <https://github.com/CarterPerez-dev/fullstack-template/blob/documentation/docs/wiki/nginx.md>`_

  Reverse proxy setup, rate limiting, WebSocket proxying, caching strategies, security headers, and performance tuning for both development and production.

- `Docker & Compose <https://github.com/CarterPerez-dev/fullstack-template/blob/documentation/docs/wiki/docker.md>`_

  Multi-stage Dockerfiles, health checks, network segmentation, resource limits, security hardening, and complete containerization guide.

----

License
=======

MIT License - see - `LICENSE <https://github.com/CarterPerez-dev/fullstack-template/blob/documentation/docs/templates/LICENSE>`_
