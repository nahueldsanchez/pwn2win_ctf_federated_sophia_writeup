import torch
from torch import nn
from torch import optim
import syft as sy
from syft.workers.websocket_client import WebsocketClientWorker
from data import data, train

def main():
    hook = sy.TorchHook(torch)
    squad = WebsocketClientWorker(id=1,
            host='localhost',
            port=7171,
            hook=hook,
            verbose=True)

    message = data
    message_ptr = message.send(squad)
    print(message_ptr)
    print('sent model data. now squad has %d objects'%(message_ptr.location.objects_count_remote()))

    # get squad updated model
    model = nn.Linear(1,1)
    train(model)

if __name__ == '__main__':
    main()
