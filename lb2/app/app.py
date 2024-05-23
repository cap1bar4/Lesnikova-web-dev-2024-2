from flask import Flask, render_template, request, make_response

app = Flask(__name__)
application = app


@app.route('/')
def index():
    url = request.url
    return render_template('index.html', url=url)

@app.route('/args')
def args():
    return render_template('args.html')

@app.route('/headers')
def headers():
    return render_template('headers.html')

@app.route('/cookies')
def cookies():
    response = make_response(render_template('cookies.html'))
    if "User"  not in request.cookies:
        response.set_cookie("User","Hello World!")
    else:
        response.delete_cookie("User")
    return response

@app.route("/form", methods = ["POST", "GET"])
def form():
    return render_template("forms.html")

@app.route("/calc", methods = ["POST", "GET"])
def calc():
    res = 0
    error = ''
    if request.method == "POST":
        try:
            a = float(request.form['a'])
            op = request.form['operation']
            b = float(request.form['b'])
            match op:
                case '+':
                    res = a + b
                case '-':
                    res = a - b
                case '/':
                    res = a / b
                case '*':
                    res = a * b
        except ZeroDivisionError:
            error = 'Деление на 0 невозможно'
        except ValueError: 
            error = 'Неверный тип данных'
        
    return render_template("calc.html", res = res, error = error)

@app.route("/mob_number", methods = ["POST", "GET"])
def mob_number():
    mobile_num = ''
    msg = ''
    error = ''
    num_of_num = ''
    input_cls = ''
    count = 0

    if request.method == "POST":
        mobile_num = request.form.get('mobile_num')
        print(mobile_num)
        num_list = ['0', '1', '2', '3', '4','5', '6', '7', '8', '9'] 
        sym_list = [' ', '(', ')', '-', '+', '.']

        for s in mobile_num:
            if s in num_list:
                count += 1
                num_of_num += s

            if s not in num_list and s not in sym_list:
                error = "Недопустимый ввод. В номере телефона встречаются недопустимые символы."
                input_cls = 'is-invalid'
                return render_template("mob_number.html", mobile_num = mobile_num, error = error, input_cls = input_cls)
                
        if mobile_num[0] == '8' and count == 11:
            mobile_num = "8-{}-{}-{}-{}".format(num_of_num[1:4], num_of_num[4:7], num_of_num[7:9], num_of_num[9:])
            input_cls = 'is-valid'
        elif mobile_num[:2] == '+7' and count == 11:
            mobile_num = "8-{}-{}-{}-{}".format(num_of_num[1:4], num_of_num[4:7], num_of_num[7:9], num_of_num[9:])
            input_cls = 'is-valid'
        elif mobile_num[:2] != '+7' and count == 10:
            mobile_num = "8-{}-{}-{}-{}".format(num_of_num[0:3], num_of_num[3:6], num_of_num[6:8], num_of_num[8:])
            input_cls = 'is-valid'
        else:
            error = 'Недопустимый ввод. Неверное количество цифр.'
            input_cls = 'is-invalid'

    return render_template("mob_number.html", mobile_num = mobile_num, error = error, input_cls = input_cls)

    
