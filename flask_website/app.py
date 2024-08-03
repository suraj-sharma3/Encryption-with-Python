from flask import Flask, render_template, request
from lightphe import LightPHE

app = Flask(__name__)

enc_add_algo = LightPHE(algorithm_name="Paillier")
enc_mult_algo = LightPHE(algorithm_name="RSA")

num_cip1 = 0
num_cip2 = 0
result_add_cip = None
result_multiply_cip = None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    global num_cip1, num_cip2

    num1 = int(request.form['num1'])
    num2 = int(request.form['num2'])

    num_cip1 = enc_add_algo.encrypt(plaintext=num1)
    num_cip2 = enc_add_algo.encrypt(plaintext=num2)

    return render_template('result.html', cip_num1=num_cip1, cip_num2=num_cip2)

@app.route('/add', methods=['POST'])
def add():
    num1 = int(request.form['num1'])
    num2 = int(request.form['num2'])

    result_add = num1 + num2
    return render_template('index.html', result_add=result_add, num1=num1, num2=num2)

@app.route('/multiply', methods=['POST'])
def multiply():
    num1 = int(request.form['num1'])
    num2 = int(request.form['num2'])

    result_multiply = num1 * num2
    return render_template('index.html', result_multiply=result_multiply, num1=num1, num2=num2)

@app.route('/decrypt', methods=['POST'])
def decrypt():
    global num_cip1, num_cip2

    decrypted_value_1 = enc_add_algo.decrypt(num_cip1)
    decrypted_value_2 = enc_add_algo.decrypt(num_cip2)

    return render_template('result.html', decrypted_value_1=decrypted_value_1, decrypted_value_2=decrypted_value_2, cip_num1=num_cip1, cip_num2=num_cip2)

@app.route('/add_encrypted', methods=['POST'])
def add_encrypted():
    global result_add_cip, num_cip1, num_cip2

    # Perform homomorphic addition on encrypted numbers
    if num_cip1 and num_cip2:
       result_add_cip = num_cip1 + num_cip2
    else:
       result_add_cip = None

    return render_template('result.html', result_add_encrypted_cip=result_add_cip)

@app.route('/multiply_encrypted', methods=['POST'])
def multiply_encrypted():
    global result_multiply_cip, num_cip1, num_cip2

    num_cip1 = enc_add_algo.decrypt(num_cip1)
    num_cip2 = enc_add_algo.decrypt(num_cip2)

    num_cip1 = enc_mult_algo.encrypt(num_cip1)
    num_cip2 = enc_mult_algo.encrypt(num_cip2)

    # Perform homomorphic multiplication on encrypted numbers
    if num_cip1 and num_cip2:
        result_multiply_cip = num_cip1 * num_cip2
    else:
        result_multiply_cip = None

    return render_template('result.html', result_multiply_encrypted_cip=result_multiply_cip)

@app.route('/decrypt_add', methods=['POST'])
def decrypt_add():
    global result_add_cip

    if result_add_cip is not None:
        decrypted_add_result = enc_add_algo.decrypt(result_add_cip)
    else:
        decrypted_add_result = None

    return render_template('result.html', result_add_encrypted_cip=result_add_cip, decrypted_add_result=decrypted_add_result)

@app.route('/decrypt_multiply', methods=['POST'])
def decrypt_multiply():
    global result_multiply_cip

    if result_multiply_cip is not None:
        decrypted_multiply_result = enc_mult_algo.decrypt(result_multiply_cip)
    else:
        decrypted_multiply_result = None

    return render_template('result.html', result_multiply_encrypted_cip=result_multiply_cip, decrypted_multiply_result=decrypted_multiply_result)

if __name__ == '__main__':
    app.run(debug=True)

