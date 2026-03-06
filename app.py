from flask import Flask, request, render_template
import scanner

app = Flask(__name__)

@app.route("/", methods=["GET","POST"])
def home():

    result=None

    if request.method=="POST":

        url=request.form.get("url")
        message=request.form.get("message")

        result=scanner.scan_data(url,message)

    return render_template("index.html",result=result)

if __name__=="__main__":
    app.run(debug=True)