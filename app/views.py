# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

# Flask modules
from re import A
from flask   import render_template, request
from jinja2  import TemplateNotFound

# App modules
from app import app
from app.process import all, dna
# App main route + generic routing
@app.route('/', defaults={'path': 'index.html'})
@app.route('/<path>')
def index(path):

    try:

        # Detect the current page
        segment = get_segment( request )

        # Serve the file (if exists) from app/templates/home/FILE.html
        return render_template( 'home/' + path, segment=segment )
    
    except TemplateNotFound:
        return render_template('home/page-404.html'), 404

@app.route('/test/time/<path>', methods=['POST','GET'])
def testEnc(path):

    try:
        if (request.method == 'POST'):
            parameter = request.form
            # print(parameter,flush=True)
            input = []
            for i in parameter:
                input.append(parameter[i])
            input.pop()
            # print(input)
            # print(path)
            # result = []
            if path == "normal":
                result = all.testEncNormal(input,path)
                algorithm = ["NTRU","ECC","El Gamal","RSA"]
            elif path == "dna":
                result = all.testEncDNA(input,path)
                algorithm = ["NTRU","ECC","El Gamal","RSA"]
            elif path == "dna-crypt":
                result = all.testdnaCrypt(input,path)
                algorithm = ["NTRU","ECC","El Gamal","RSA"]
            # print(result)
            return render_template( "process/test/enc/"+path+"/" + "time" +"_result" +".html", inputParameter=input, result=result,algorithm=algorithm)
        # Detect the current page
        segment = get_segment( request )
        # Serve the file (if exists) from app/templates/home/FILE.html
        return render_template( "process/test/enc/" +path+"/"+ "time"  +".html", segment=segment )
    
    except TemplateNotFound:
        return render_template('home/page-404.html'), 404


@app.route('/test/analysis/<path>', methods=['POST','GET'])
def testEncAnalysis(path):

    try:
        if (request.method == 'POST'):
            
            parameter = request.form
            input = []
            for i in parameter:
                input.append(parameter[i])
            input.pop()
            if (path == "enc") :
                algorithm = ["NTRU","ECC","El Gamal","RSA"]
                size = ["10 Bytes","100 Bytes","1000 Bytes","10000 Bytes","100000 Bytes"]
                result = all.testEncAnalysis(input)
            elif path == "encDna" :
                algorithm = ["NTRU-DNA","ECC-DNA","El Gamal-DNA","RSA-DNA"]
                size = ["1 Bytes","10 Bytes","100 Bytes","1000 Bytes","10000 Bytes"]
                result = all.testEncDnaAnalysis(input)
            #print(result)
            return render_template( "process/test/" + "analysis/"+ path +"_result" +".html", algorithm=algorithm,inputParameter=input, result=result, size=size)
        # Detect the current page
        segment = get_segment( request )
        # Serve the file (if exists) from app/templates/home/FILE.html
        return render_template( "process/test/" + "analysis/" + path +".html", segment=segment )
    
    except TemplateNotFound:
        return render_template('home/page-404.html'), 404


@app.route('/normal/<method>/<path>', methods=['POST','GET'])
def normalEnc(method, path):

    try:
        if (request.method == 'POST'):
            parameter = request.form
            # print(parameter,flush=True)
            input = []
            for i in parameter:
                input.append(parameter[i])
            input.pop()
            
            # print(path)
            result = all.encNormal(input,path)
            return render_template( "process/normal/" + method +"/"+ path+"_result" +".html", inputParameter=input, result=result)
        # Detect the current page
        segment = get_segment( request )
        # Serve the file (if exists) from app/templates/home/FILE.html
        return render_template( "process/normal/" + method +"/"+ path +".html", segment=segment )
    
    except TemplateNotFound:
        return render_template('home/page-404.html'), 404



@app.route('/dna/<method>/<path>', methods=['POST','GET'])
def dnaEnc(method, path):

    try:
        if (request.method == 'POST'):
            parameter = request.form
            # print(parameter,flush=True)
            input = []
            for i in parameter:
                input.append(parameter[i])
            input.pop()
            # print(path)
            if method == "enc":
                result = all.encDNA(input,path)
            
            # print(input[1])
            return render_template( "process/dna/" + method +"/"+ path+"_result" +".html", inputParameter=input, result=result)
        # Detect the current page
        segment = get_segment( request )
        # Serve the file (if exists) from app/templates/home/FILE.html
        return render_template( "process/dna/" + method +"/"+ path +".html", segment=segment )
    
    except TemplateNotFound:
        return render_template('home/page-404.html'), 404


    except TemplateNotFound:
        return render_template('home/page-404.html'), 404



def get_segment( request ): 

    try:

        segment = request.path.split('/')[-1]

        if segment == '':
            segment = 'index'

        return segment    

    except:
        return None  
