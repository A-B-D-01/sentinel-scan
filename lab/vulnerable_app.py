from flask import Flask, request

app = Flask(__name__)


@app.route("/")
def home():

    return """
    <html>
    <head>
        <title>Local Security Lab</title>
    </head>

    <body>

        <h1>SentinelScan Security Lab</h1>

        <p>This is a local test application.</p>

        <form action="/search" method="GET">

            <input
                name="q"
                placeholder="Search test data"
            >

            <button type="submit">
                Search
            </button>

        </form>

    </body>
    </html>
    """


@app.route("/search")
def search():

    query = request.args.get("q", "")

    return f"""
    <html>
    <body>

        <h1>Search Results</h1>

        <p>Search query: {query}</p>

    </body>
    </html>
    """


if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=8000,
        debug=False
    )