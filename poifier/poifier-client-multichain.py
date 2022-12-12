########################################################################
# POIfier-client - script to upload POI to POIfier-server
# author: Grassets-tech
# contact: contact@grassets.tech
########################################################################
#!/usr/bin/env python3

from python_graphql_client import GraphqlClient
from string import Template
from urllib.parse import urljoin
import argparse
import json
import logging
import os
import requests
import sys
import time
import toml
from hdwallet import HDWallet
from hdwallet.symbols import ETH
from eth_account.messages import encode_defunct
from web3 import Web3

logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s',level=logging.INFO)
INDEXER_REF = '0x0000000000000000000000000000000000000000'
LAST_N_EPOCH = 10
LAST_N_1K_BLOCK = 10
SLEEP = 14400 # Run script every 4 hrs

CAIP2_BY_CHAIN_AlIAS = {
  'mainnet': 'eip155:1',
  'goerli': 'eip155:5',
  'gnosis': 'eip155:100',  
}
CHAIN_BY_CAIP2_AlIAS = {
  'eip155:1': 'mainnet',
  'eip155:5': 'goerli',
  'eip155:100': 'gnosis',  
}
PAYLOADS_GET_BLOCK_BY_NUMBER_MAINNET = {
        'method': 'eth_getBlockByNumber',
        'params': ['{}', False],
        'jsonrpc': '2.0',
        'id': 1,
    }
PAYLOADS_GET_BLOCK_BY_NUMBER_GOERLI = {
        'method': 'eth_getBlockByNumber',
        'params': ['{}', False],
        'jsonrpc': '2.0',
        'id': 1,
    }
PAYLOADS_GET_BLOCK_BY_NUMBER_GNOSIS = {
        'method': 'eth_getBlockByNumber',
        'params': ['{}', False],
        'jsonrpc': '2.0',
        'id': 1,
    }
PAYLOADS_GET_BLOCK_BY_NUMBER = {
    'mainnet': PAYLOADS_GET_BLOCK_BY_NUMBER_MAINNET,
    'goerli': PAYLOADS_GET_BLOCK_BY_NUMBER_GOERLI,
    'gnosis': PAYLOADS_GET_BLOCK_BY_NUMBER_GNOSIS,
}
PAYLOADS_GET_BLOCK_MAINNET = {
        'method': 'eth_blockNumber',
        'params': [],
        'jsonrpc': '2.0',
        'id': 1,
    }
PAYLOADS_GET_BLOCK_GOERLI = {
        'method': 'eth_blockNumber',
        'params': [],
        'jsonrpc': '2.0',
        'id': 1,
    }
PAYLOADS_GET_BLOCK_GNOSIS = {
        'method': 'eth_blockNumber',
        'params': [],
        'jsonrpc': '2.0',
        'id': 1,
    }
PAYLOADS_GET_BLOCK = {
    'mainnet': PAYLOADS_GET_BLOCK_MAINNET,
    'goerli': PAYLOADS_GET_BLOCK_GOERLI,
    'gnosis': PAYLOADS_GET_BLOCK_GNOSIS,
}

def parseArguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('--graph-node-status-endpoint',
        dest='graph_node_status_endpoint',
        help='Graph-node status endpoint, (default: %(default)s)',
        default='http://index-node-0:8030/graphql',
        type=str)
    parser.add_argument('--poifier-token-network',
        dest='poifier_token_network',
        help='Ethereum chain to get sign message Auth token, request token via POIfier portal',
        type=str)
    parser.add_argument('--poifier-token',
        dest='poifier_token',
        help='Auth token, request token via POIfier portal',
        type=str)
    parser.add_argument('--poifier-server',
        dest='poifier_server',
        help='URL of POIfier server (default: %(default)s)',
        default='https://poifier.io',
        type=str)
    parser.add_argument('--subgraph-endpoint',
        dest='subgraph_endpoint',
        help='Graph network endpoint (default: %(default)s)',
        default='https://gateway.network.thegraph.com/network',
        type=str)
    parser.add_argument('--graph-node-config',
        dest='graph_node_config',
        help='Graph node config toml file (default: %(default)s)',
        default='/root/graph-node-configs/config.toml',
        required=True,
        type=str)
    parser.add_argument('--ethereum-network',
        dest='ethereum_network',
        help='Ethereum network mainnet or goerli (default: %(default)s)',
        default='mainnet',
        type=str)
    parser.add_argument('--epoch-subgraph-endpoint',
        dest='epoch_subgraph_endpoint',
        help='Epoch subgraph for Epoch Oracle (default: %(default)s)',
        default='mainnet',
        type=str)   
    parser.add_argument('--mnemonic',
        dest='mnemonic',
        help='Operator mnemonic',
        type=str)
    parser.add_argument('--indexer-address',
        dest='indexer_address',
        help='Indexer address',
        type=str) 
    return parser.parse_args()

def getNetworksFromToml(args):
    """ Gets list of supported chains/networks from graph node toml file. """
    data = toml.load(args.graph_node_config)
    networks = {}
    for key, value in data['chains'].items():
        if key != 'ingestor':
            networks[key] = value['provider'][0]['url']
    return networks

def getToken(mnemonic, networks, indexer_address, poifier_token_network):
    """ Gets token for uploading poi to poifier server. """
    hdwallet = HDWallet(symbol=ETH)
    hdwallet.from_mnemonic(mnemonic=mnemonic)
    hdwallet.from_path(path="m/44'/60'/0'/0/0")
    private_key = hdwallet.private_key()

    web3 = Web3(Web3.HTTPProvider(networks[poifier_token_network]))
    msghash = encode_defunct(text='RYABINA_POI_HUB')
    sign_hash = web3.eth.account.sign_message(msghash, private_key)
    logging.info('Message signed with: {}'.format(sign_hash.signature.hex()))
    return '{}:{}'.format(indexer_address,sign_hash)

def getSubgraphs(graphql_endpoint):
    """ Gets subgraphs from the given node.

    Queries local node DB and gets subgraphs grouped by network.
    
    Returns: Dictionary of list of subgraphs, example: {'goerli': [Qm1, Qm2], 'gnosis': [Qm3, Qm4]}
    """
    client = GraphqlClient(endpoint=graphql_endpoint)
    subgraphs = []
    query = "{indexingStatuses {subgraph chains {network}}}"
    logging.info('Quering subgraphs endpoint: {} query: {}'.format(graphql_endpoint, query))
    try:
        data = client.execute(query=query)
    except requests.exceptions.RequestException as e:
        logging.error('Can\'t get subgraphs, check endpoint {}'.format(e))
        sys.exit()
    if data.get('errors'):
        logging.error('Can\'t get subgraphs, check query {}'.format(data))
        sys.exit()
    logging.info('Received subgraphs data: {}'.format(data))
    if data:
        subgraphs = {}
        for subgraph in data['data']['indexingStatuses']:
            network = subgraph['chains'][0]['network']
            if not subgraphs.get(network):
                subgraphs[network] = [subgraph['subgraph']]
            else:
                subgraphs[network].append(subgraph['subgraph'])
    return subgraphs

def getCurrentEpochFromOracle(epoch_subgraph_endpoint):
    """ Gets curent epoch from Epoch Manager subgraph. """
    client = GraphqlClient(endpoint=epoch_subgraph_endpoint)
    query = """
          query network{
            networks {
              latestValidBlockNumber {
                epochNumber
               }
            }
          }
    """
    logging.info('Quering currentEpoch endpoint: {} query: {}'.format(epoch_subgraph_endpoint, query))
    try:
        data = client.execute(query=query)
    except requests.exceptions.RequestException as e:
        logging.error('Can\'t get current Epoch, check endpoint {}'.format(e))
        sys.exit()
    if data.get('errors'):
        logging.error('Can\'t get current Epoch, check query {}'.format(data))
        sys.exit()
    logging.info('Received currentEpoch data: {}'.format(data))
    return int(data['data']['networks'][0]['latestValidBlockNumber']['epochNumber'])

def getStartBlockFromOracle(epoch, subgraph_endpoint):
    """ Gets start block for each chain from Epoch Manager subgraph.
    
    Returns: Dictionary {'chain': 'block'}, eg. {'mainnet': 12334, 'gnosis': 2222}
    """
    t = Template("""query StartBlock { epoch (id: $epoch){ id blockNumbers { blockNumber network {id}}}}""")
    client = GraphqlClient(endpoint=subgraph_endpoint)
    query = t.substitute(epoch=epoch)
    logging.info('Quering currentEpoch endpoint: {} query: {}'.format(subgraph_endpoint, query))
    try:
        data = client.execute(query=query)
    except requests.exceptions.RequestException as e:
        logging.error('Can\'t get current Epoch, check endpoint {}'.format(e))
        sys.exit()
    if data.get('errors'):
        logging.error('Can\'t get current Epoch, check query {}'.format(data))
        sys.exit()
    logging.info('Received currentEpoch data: {}'.format(data))
    blocknumbers = data['data']['epoch']['blockNumbers']
    blocks = {}
    for caip2, chain in CHAIN_BY_CAIP2_AlIAS.items():
        for blocknumber in blocknumbers:
            print(blocknumber) 
            if blocknumber['network']['id'] == caip2:
                blocks[chain] = blocknumber['blockNumber']
    return blocks

def getBlockHash(block_number, endpoint, payload):
    """ Gets blockhash for given block for given chain. """
    payload['params'][0] = payload['params'][0].format(hex(int(block_number)))   
    logging.info('Quering Block hash: {} query: {}'.format(endpoint, payload))
    try:
        response = requests.post(endpoint, json=payload).json()
    except requests.exceptions.RequestException as e:
        logging.error('Can\'t get Block hash, check connection {}'.format(e))
        sys.exit()
    if response.get('error'):
        logging.error('Can\'t get Block hash, check endpoint {}'.format(response))
        sys.exit()
    if not response.get('result'):
        logging.error('Can\'t get Block hash, check block number {}'.format(response))
        sys.exit()
    logging.info('Received Block hash: {}'.format(response['result']['hash']))
    return response['result']['hash']

def getCurrentBlock(networks):
    """ Gets latest blocks for each chain supported by graph node.
    
    Returns: Dictionary {'network': 'block'}
    """
    current_blocks = {}
    for network, url in networks.items():
        try:
            response = requests.post(url, json=PAYLOADS_GET_BLOCK[network]).json()
        except requests.exceptions.RequestException as e:
            logging.error('Can\'t get Block, check connection {}'.format(e))
            sys.exit()
        if response.get('error'):
            logging.error('Can\'t get Block, check endpoint {}'.format(response))
            sys.exit()
        if not response.get('result'):
            logging.error('Can\'t get Block {}'.format(response))
            sys.exit()
        logging.info('Received Block: {}'.format(response.get('result')))
        current_blocks[network] = int(response['result'], 16)
    return current_blocks

def getPoi(indexer_id, block_number, block_hash, subgraph_ipfs_hash, graphql_endpoint):
    """ Gets POI from graph node DB for given subgraph for given block. """
    poi = ''
    client = GraphqlClient(endpoint=graphql_endpoint)
    t = Template("""query RefPOI {
        proofOfIndexing(
          subgraph: "$subgraph_ipfs_hash",
          blockNumber: $block_number,
          blockHash: "$block_hash",
          indexer: "$indexer_id")
       }""")
    query = t.substitute(subgraph_ipfs_hash=subgraph_ipfs_hash,
                              block_number=block_number,
                              block_hash=block_hash,
                              indexer_id=indexer_id)
    logging.info('Quering POI endpoint: {} query: {}'.format(graphql_endpoint, query))
    try:
        data = client.execute(query=query)
    except requests.exceptions.RequestException as e:
        logging.error('Can\'t get POI, check endpoint {}'.format(e))
        sys.exit()
    logging.info('Received POI data: {}'.format(data))
    if data.get('errors'):
        logging.error('Can\'t get POI, check query {}'.format(data))
        sys.exit()
    if len(data.get('data')) == 0:
        logging.error('Can\'t get POI, check endpoint {}'.format(e))
        sys.exit()
    poi = data['data']['proofOfIndexing']
    if not poi:
        logging.info('Warning: no POI found for subgraph {}'.format(subgraph_ipfs_hash))
    return poi

def uploadPoi(poifier_server_url, token, report):
    """ Uploads POI report to the poifier server. """
    headers = {
    "Content-Type": "application/json",
    "token": token
    }
    poifier_server_url_api = urljoin(poifier_server_url, '/api/poi')
    try:
        r = requests.post(poifier_server_url_api, headers=headers, json=report)
    except Exception as e:
        logging.error('Failed to upload POI report {}'.format(e))
        return
    if r.status_code != 200:
        logging.error('Failed to upload POI report to poifier-server: {}, Error: {}, {}'.format(poifier_server_url_api, r.status_code, r.text))
        return
    logging.info('POI report uploaded to poifier-server: {}'.format(poifier_server_url_api))

def getEpochBlockRangeFromOracle(epoch_range, args, networks):
    """ Gets hash for each start block for given epochs in a range.

    Returns: Example {'mainnet': [{'epoch': 163, 'block': 1000, 'hash': '0x123'}, 
                                  {'epoch': 164, 'block': 2000, 'hash': '0x222'}]}
    """
    epoch_block_range = {}
    for epoch in epoch_range:
        block_numbers = getStartBlockFromOracle(epoch, args.epoch_subgraph_endpoint) # returns dict {'network': block}
        for network, block_number in block_numbers.items():
            if networks.get(network):
                block_hash = getBlockHash(block_number, networks[network], PAYLOADS_GET_BLOCK_BY_NUMBER[network])
                if not epoch_block_range.get(network):
                    epoch_block_range[network] = [{'epoch': epoch, 'block': block_number, 'hash': block_hash}]
                else:
                    epoch_block_range[network].append({'epoch': epoch, 'block': block_number, 'hash': block_hash})
    return  epoch_block_range

def getBlockHashRange(block_ranges, networks):
    """ Gets hash for each block for given block in a range.

    Returns: Example {'mainnet': [{'block': 1000, 'hash': '0x123'}, 
                                  {'164, 'block': 2000, 'hash': '0x222'}],
                      'goerli': [{'block': 1000, 'hash': '0x123'}, 
                                  {'164, 'block': 2000, 'hash': '0x222'}]
                    }
    """
    block_hash_range = {}
    for network, block_numbers in block_ranges.items():
        if networks.get(network):
            for block_number in block_numbers:
                block_hash = getBlockHash(block_number, networks[network], PAYLOADS_GET_BLOCK_BY_NUMBER[network])
                if not block_hash_range.get(network):
                    block_hash_range[network] = [{'block': block_number, 'hash': block_hash}]
                else:
                    block_hash_range[network].append({'block': block_number, 'hash': block_hash})
    return block_hash_range

def getPoiReport(subgraphs, epoch_block_range, block_hash_range, args):
    poi_report = []
    for network, subgraphs in subgraphs.items():
        for subgraph in subgraphs:
            if epoch_block_range.get(network):
                for epoch in epoch_block_range[network]:
                    poi = getPoi(INDEXER_REF, epoch['block'], epoch['hash'], subgraph, args.graph_node_status_endpoint)
                    if poi:
                        poi_report.append({'epoch':epoch['epoch'], 'block': epoch['block'], 'deployment': subgraph, 'poi': poi})
            if block_hash_range.get(network):
                for block in block_hash_range[network]:
                    poi = getPoi(INDEXER_REF, block['block'], block['hash'], subgraph, args.graph_node_status_endpoint)
                    if poi:
                        poi_report.append({'block':block['block'], 'deployment': subgraph, 'poi': poi})
    return poi_report

def getSummary(poi_report):
    deployments_count = len(set([i['deployment'] for i in poi_report]))
    records_count = len(poi_report)
    return deployments_count, records_count

def block_range(current_block):
    block_ranges = {}
    for network, current_block in current_block.items():
        block_ranges[network] = [(current_block // 1000 - i) * 1000 for i in range(0,LAST_N_1K_BLOCK)]
    return block_ranges

def main():
    while True:
        args = parseArguments()
        networks = getNetworksFromToml(args)
        subgraphs = getSubgraphs(args.graph_node_status_endpoint)
        current_epoch = getCurrentEpochFromOracle(args.epoch_subgraph_endpoint)
        current_blocks = getCurrentBlock(networks)
        epoch_range = range(current_epoch-(LAST_N_EPOCH-1), current_epoch+1)
        block_ranges = block_range(current_blocks)
        epoch_block_range = getEpochBlockRangeFromOracle(epoch_range, args, networks)
        block_hash_range = getBlockHashRange(block_ranges, networks)
        poi_report = getPoiReport(subgraphs, epoch_block_range, block_hash_range, args)
        logging.info('POI summary: deployments: {}, records: {}'.format(*getSummary(poi_report)))
        for item in poi_report:
            logging.info(item)
        if not args.poifier_token:
            getToken(args.mnemonic, networks, args.indexer_address, args.poifier_token_network)
        uploadPoi(args.poifier_server, args.poifier_token, poi_report)
        time.sleep(SLEEP)

if __name__ == "__main__":
    main()
