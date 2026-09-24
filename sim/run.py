"""Launcher: python -m sim.run --provider akamai|cloudflare --port N"""
import argparse

import uvicorn


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--provider", choices=["akamai", "cloudflare"], required=True)
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--host", default="127.0.0.1")
    args = p.parse_args()
    app = f"sim.{'akamai_app' if args.provider == 'akamai' else 'cloudflare_app'}:app"
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
