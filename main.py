from website import create_app
'''main run program'''
app,socketio=create_app()
if __name__=="__main__":
    # app.run(port=8000,debug=True)
    socketio.run(app, port=7000, debug=True)
