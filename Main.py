from tkinter import messagebox
from tkinter import *
from tkinter import simpledialog
import tkinter
import matplotlib.pyplot as plt
import lattice.falcon
from multiprocessing import Process  # load openmp as multiprocess
import timeit
import multiprocessing
import numpy as np
import pq_ntru
import logging
import time  # Import the time module

main = Tk()
main.title(
    "Design and Implementation of a Parallel Computing Framework for Efficient and Secure Lattice-Based Key Exchange Protocols")
main.geometry("1300x1200")

global sk, parallel, normal, text, tf1


def generateKey():
    global sk
    text.delete('1.0', END)
    sk = lattice.falcon.SecretKey(512)
    text.insert(END, "Lattice Secret Key : " + str(sk) + "\n\n")


def normalLattice(msg):
    global sk
    pk = lattice.falcon.PublicKey(sk)
    sig = sk.sign(msg)
    verify = pk.verify(msg, sig)
    return verify, sig


###
def normalLatticeExchange():
    global normal, sk
    text.delete('1.0', END)
    normal = 0
    message = tf1.get()
    for i in range(0, 3):
        msg = message.encode()
        start = timeit.default_timer()
        if i == 0:
            sk = lattice.falcon.SecretKey(512)
            enc = pq_ntru.encrypt("ntru_key", message)
            text.insert(END, "Encrypted Message : " + str(enc) + "\n\n")
            decrypted = pq_ntru.decrypt("ntru_key", enc)
            text.insert(END, "Decrypted Message : " + str(decrypted) + "\n\n")
        verify, sig = normalLattice(msg)
        end = timeit.default_timer()
        time = end - start
        normal = normal + time
    if verify:
        text.insert(END, "Normal Verification Successfull\n")
        text.insert(END, "Verification Signatures : " + str(sig) + "\n")
        text.insert(END, "\nNormal Lattice Key Exchange & Verification Time : " + str(normal) + " seconds\n\n")
    else:
        text.insert(END, "Normal Verification Failed\n\n")

'''
logging.basicConfig(level=logging.DEBUG)

def refined_chunking(message, num_processes):
    chunk_size = len(message) // num_processes
    chunks = [message[i:i + chunk_size] for i in range(0, len(message), chunk_size)]

    # Adjusting the last two chunks to ensure the entire message is utilized
    if len(chunks) > 1 and len(chunks[-1]) < chunk_size:
        leftover = chunks.pop()
        chunks[-1] += leftover

    return chunks


# Assuming other necessary imports are here...

def OpenMPParallel(msg, sk, i, queue):
    try:
        global verify, sig
        logging.debug(f"Process {i} started with message chunk: {msg}")

        pk = lattice.falcon.PublicKey(sk)
        sig = sk.sign(msg)
        verify = pk.verify(msg, sig)

        # Tagging the results with an identifier
        results = {'id': i, 'verify': verify, 'sig': sig, 'msg_chunk': msg}

        enc = pq_ntru.encrypt("ntru_key", msg)
        decrypted = pq_ntru.decrypt("ntru_key", enc)
        results.update({'enc': enc, 'decrypted': decrypted})

        queue.put(results)

        logging.debug(f"Process {i} completed successfully")

    except Exception as e:
        logging.exception(f"Exception occurred in process {i}")
        queue.put({"error": str(e), "id": i})


def parallelLatticeExchange():
    global text  # Declare text as global
    text.delete('1.0', 'end')

    message = tf1.get().encode()
    num_processes = 3
    chunks = refined_chunking(message, num_processes)

    queue = multiprocessing.Queue()
    processes = []

    start = time.perf_counter()

    for i, msg_chunk in enumerate(chunks):
        p = multiprocessing.Process(target=OpenMPParallel, args=(msg_chunk, sk, i, queue))
        p.start()
        processes.append(p)

    logging.info("All processes started.")
    logging.info("Waiting for all processes to complete...")

    # Join all processes
    for p in processes:
        p.join()

    logging.info("All processes have been joined. Starting to process the queue...")

    # Organizing results by their identifiers
    results = sorted([queue.get() for _ in range(queue.qsize())], key=lambda x: x['id'])

    logging.info("Organizing and processing the results...")

    decrypted_message = ""
    encrypted_message = ""

    # Extracting the data from the organized results
    for res in results:
        decrypted_message += res['decrypted'].decode()
        encrypted_message += str(res['enc']) + " "
        if res['verify']:
            text.insert('end', "Parallel Verification Successful for chunk: {}\n".format(res['msg_chunk'].decode()))
            text.insert('end', "Verification Signatures : " + str(res['sig']) + "\n\n")

    text.insert('end', "Encrypted Message : {}\n".format(encrypted_message))
    text.insert('end', "Decrypted Message : {}\n".format(decrypted_message))
    text.insert('end', "\nParallel Lattice Key Exchange & Verification Time : " + str(end - start) + " seconds\n\n")

    logging.info("parallelLatticeExchange completed successfully.")


'''
#run lattice with openmp parallel
def OpenMPParallel(msg, sk, i, queue):
    global verify, sig
    pk = lattice.falcon.PublicKey(sk)
    sig = sk.sign(msg)
    verify = pk.verify(msg, sig)

    if i == 2:
        enc = pq_ntru.encrypt("ntru_key", msg)
        decrypted = pq_ntru.decrypt("ntru_key", enc)
        queue.put(verify)
        queue.put(sig)
        queue.put(enc)
        queue.put(decrypted)
    return verify, sig


def parallelLatticeExchange():
    text.delete('1.0', END)
    global parallel
    message = tf1.get()
    queue = multiprocessing.Queue()

    processes = []

    start = time.perf_counter()  # Start timing here

    for i in range(3):
        msg = message.encode()
        p = Process(target=OpenMPParallel, args=(msg, sk, i, queue))
        p.start()
        processes.append(p)

    # Join all processes
    for p in processes:
        p.join()

    end = time.perf_counter()  # End timing here
    parallel = end - start  # Calculate the total elapsed time
    size = queue.qsize()
    print(f"[INFO] Queue currently has {size} items.")

    print("[INFO] Getting an item from the queue...")
    verify = queue.get()
    sig = queue.get()
    enc = queue.get()
    decrypted = queue.get()
    print("[INFO] Item retrieved from the queue.")

    text.insert(END,"Encrypted Message : "+str(enc)+"\n\n")
    text.insert(END,"Decrypted Message : "+str(decrypted)+"\n\n")

    if verify:
        text.insert(END, "Parallel Verification Successfull\n")
        text.insert(END,"Verification Signatures : "+str(sig)+"\n")
        text.insert(END,"\nParallel Lattice Key Exchange & Verification Time : "+str(parallel)+" seconds\n\n")
    else:
        text.insert(END,"Parallel Verification Failed\n\n")



def graph():
    height = [normal, parallel]
    bars = ('Normal Lattice Key Verification', 'Parallel Lattice Key Verification')
    y_pos = np.arange(len(bars))
    plt.bar(y_pos, height)
    plt.xticks(y_pos, bars)
    plt.title("Normal & Parallel Lagttice Key Verification Time Graph")
    plt.show()


def close():
    main.destroy()


def runGUI():
    global text, tf1

    font = ('times', 15, 'bold')
    title = Label(main,
                  text='Design and Implementation of a Parallel Computing Framework for Efficient and Secure Lattice-Based Key Exchange Protocols')
    title.config(bg='mint cream', fg='olive drab')
    title.config(font=font)
    title.config(height=3, width=120)
    title.place(x=0, y=5)

    font1 = ('times', 14, 'bold')
    ff = ('times', 12, 'bold')

    l1 = Label(main, text='Secret Message:')
    l1.config(font=font1)
    l1.place(x=50, y=100)

    tf1 = Entry(main, width=40)
    tf1.config(font=font1)
    tf1.place(x=230, y=100)

    generateButton = Button(main, text="Generate Lattice Secret Key", command=generateKey)
    generateButton.place(x=50, y=150)
    generateButton.config(font=ff)

    normalButton = Button(main, text="Normal Lattice Key Exchange & Verification", command=normalLatticeExchange)
    normalButton.place(x=330, y=150)
    normalButton.config(font=ff)

    parallelButton = Button(main, text="OpenMP Lattice Key Exchange & Verification", command=parallelLatticeExchange)
    parallelButton.place(x=710, y=150)
    parallelButton.config(font=ff)

    graphButton = Button(main, text="Execution Time Graph", command=graph)
    graphButton.place(x=50, y=200)
    graphButton.config(font=ff)

    exitButton = Button(main, text="Exit", command=close)
    exitButton.place(x=330, y=200)
    exitButton.config(font=ff)

    font1 = ('times', 13, 'bold')
    text = Text(main, height=22, width=100)
    scroll = Scrollbar(text)
    text.configure(yscrollcommand=scroll.set)
    text.place(x=10, y=250)
    text.config(font=font1)

    main.config(bg='gainsboro')
    main.mainloop()


if __name__ == '__main__':
    runGUI()
