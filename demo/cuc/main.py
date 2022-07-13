from littleRedCUC import create_app

app = create_app()

if __name__ == '__main__':
    app.run(debug=True,ssl_context=("./x.509/self-signed/self-signed-key.pem", './x.509/self-signed/key.pem'))