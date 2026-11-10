import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from vulnscope.adapters.inbound.http.app import create_app


if __name__ == "__main__":
    app = create_app()
    app.run(debug=True, port=5000)
