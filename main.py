import graphviz

"""
Write a parser for parsing sysdig output logs, and output the correctly parsed information
line by line in the report. (30 points)
a. The parser can extract the values of different fields from the log entries correctly
b. The parser should construct 3-tuples <subject, operation, object> to represent each
log entry (in Java or Python)
• Subject with unique identifiers: process entity
    • Process unique identifier: PID, process name
• Operation: system call operations, such as read, write, send, receive
• Object with unique identifiers: process entity, files, IP addresses
    • Process unique identifier: PID, process name
    • File unique identifier: file name
    • IP address unique identifier: source IP, source port, destination IP, destination port, protocol
"""


# sudo sysdig -p *"%proc.pid %proc.name %evt.rawtime %evt.latency %evt.type %fd.name %fd.cip %fd.cport %fd.rip %fd.rport %fd.l4proto"  "proc.name!=tmux and (evt.type=read or evt.type=write)" and proc.name!=sysdig > filename_new.txt

log_data = {}
input_file_name = 'check.txt'
back_track_data = {}

destination_source_input_dict = {}

done_items = []


def read():
    output = ""
    with open(input_file_name, 'r') as f:
        line = f.readline()
        while line:
            data = line.split(' ')
            pid = data[0]
            pname = data[1]
            start_time = data[2]
            latency = data[3]
            event_type = data[4]
            obj_pname = data[5]
            if 'pipe' in obj_pname and obj_pname != 'pipe':
                obj_pname = 'pipe'
            elif '' == obj_pname:
                obj_pname = "Unknown node"
            s_ip = data[6]
            s_port = data[7]
            c_ip = data[8]
            c_port = data[9]
            protocol = data[10]

            subject = pname + pid

            if subject in log_data and event_type in log_data[subject]:
                log_data[subject][event_type].append({
                        'start_time': start_time,
                        'latency': latency,
                        'obj_pname': obj_pname,
                        'network_data': {
                            's_ip': s_ip,
                            's_port': s_port,
                            'c_ip': c_ip,
                            'c_port': c_port,
                            'protocol': protocol
                        },
                        'pid': pid
                    })
            elif subject in log_data:
                log_data[subject][event_type] = [{
                    'start_time': start_time,
                    'latency': latency,
                    'obj_pname': obj_pname,
                    'network_data': {
                        's_ip': s_ip,
                        's_port': s_port,
                        'c_ip': c_ip,
                        'c_port': c_port,
                        'protocol': protocol
                    },
                    'pid': pid
                }]
            else:
                log_data[subject] = {
                    event_type: [{
                        'start_time': start_time,
                        'latency': latency,
                        'obj_pname': obj_pname,
                        'network_data': {
                            's_ip': s_ip,
                            's_port': s_port,
                            'c_ip': c_ip,
                            'c_port': c_port,
                            'protocol': protocol
                        },
                        'pid': pid
                    }]
                }

            subject, obj_pname = obj_pname, subject
            if subject in destination_source_input_dict and event_type in destination_source_input_dict[subject]:
                destination_source_input_dict[subject][event_type].append({
                        'start_time': start_time,
                        'latency': latency,
                        'obj_pname': obj_pname,
                        'network_data': {
                            's_ip': s_ip,
                            's_port': s_port,
                            'c_ip': c_ip,
                            'c_port': c_port,
                            'protocol': protocol
                        },
                        'pid': pid
                    })
            elif subject in destination_source_input_dict:
                destination_source_input_dict[subject][event_type] = [{
                    'start_time': start_time,
                    'latency': latency,
                    'obj_pname': obj_pname,
                    'network_data': {
                        's_ip': s_ip,
                        's_port': s_port,
                        'c_ip': c_ip,
                        'c_port': c_port,
                        'protocol': protocol
                    },
                    'pid': pid
                }]
            else:
                destination_source_input_dict[subject] = {
                    event_type: [{
                        'start_time': start_time,
                        'latency': latency,
                        'obj_pname': obj_pname,
                        'network_data': {
                            's_ip': s_ip,
                            's_port': s_port,
                            'c_ip': c_ip,
                            'c_port': c_port,
                            'protocol': protocol
                        },
                        'pid': pid
                    }]
                }
            
            output = output + str(((pid, pname), event_type, {
                'process name': obj_pname,
                'file name':  obj_pname,
                'source IP': s_ip,
                'source port': s_port,
                'destination IP': c_ip,
                'destination port': c_port,
                'protocol': protocol
            })) + "\n"
            line = f.readline()
    with open('output.txt', 'w') as outFile:
        outFile.write(output)

def graph(log_data, file_name):
    dot = graphviz.Digraph(comment='mini log')

    for k, v in log_data.items():
        dot.node(k, k)
        for action in v:
            nodes = v[action]
            nodes = sorted(nodes, key=lambda d: int(d['start_time']))
            for node in nodes:
                dot.node(node['obj_pname'], node['obj_pname'])
                label = str(int(node['start_time']) // pow(10, 9)) + " => " + str((int(node['start_time']) + int(node['latency'])) // pow(10, 9))
                if action == 'write':
                    dot.edge(k, node['obj_pname'], label=label, color="red")
                else:
                    dot.edge(node['obj_pname'], k, label=label, color="blue")

    # print(dot)
    dot.render('doctest-output/' + file_name + '.gv', view=True)
    'doctest-output/.gv.pdf'


def backtrack(e_node, timestamp):
    print(f"Backtracking edge that ends in {e_node} around time: {timestamp}")
    # if e_node not in destination_source_input_dict and e_node not in log_data:
    #     print("Not present")
    #     return
    if e_node in destination_source_input_dict:
        write_processes = destination_source_input_dict[e_node]['write'] if 'write' in destination_source_input_dict[e_node] else None
        if write_processes:
            filtered_write_processes = []
            for item in write_processes:
                if int(item['start_time']) // pow(10, 9) <= timestamp:
                    filtered_write_processes.append(item)
            write_processes = filtered_write_processes
            for proc in write_processes:
                # print(proc)
                proc = proc.copy()
                s_node = proc['obj_pname']
                proc['obj_pname'] = e_node

                # import pdb
                # pdb.set_trace()

                if s_node in back_track_data and 'read' in back_track_data[s_node]:
                    back_track_data[s_node]['write'].append(proc)
                elif s_node in back_track_data:
                    back_track_data[s_node]['write'] = [proc]
                else:
                    back_track_data[s_node] = {
                        'write': [proc]
                    }
                if(s_node not in done_items):
                    done_items.append(s_node)
                    backtrack(s_node, timestamp)
    if e_node in log_data:
        read_processes = log_data[e_node]['read'] if 'read' in log_data[e_node] else None
        if read_processes:
            filtered_read_processes = []
            for item in read_processes:
                if int(item['start_time']) // pow(10, 9) <= timestamp:
                    filtered_read_processes.append(item)
            read_processes = filtered_read_processes
            for proc in read_processes:
                proc = proc.copy()
                s_node = proc['obj_pname']
                proc['obj_pname'] = e_node
                if s_node in back_track_data and 'write' in back_track_data[s_node]:
                    back_track_data[s_node]['write'].append(proc)
                elif s_node in back_track_data:
                    back_track_data[s_node]['write'] = [proc]
                else:
                    back_track_data[s_node] = {
                        'write': [proc]
                    }
                if(s_node not in done_items):
                    done_items.append(s_node)
                    backtrack(s_node, timestamp)



def find_edge(s_node, e_node):
    print(f"Looking for initial edge {s_node} => {e_node}")
    read_processes = log_data[s_node]['read'] if 'read' in log_data[s_node] else None
    write_processes = log_data[s_node]['write'] if 'write' in log_data[s_node] else None
    last_edge = None
    if read_processes:
        read_processes = list(filter(lambda d: (e_node == d['obj_pname']), read_processes))
        read_processes = sorted(read_processes, key=lambda d: int(d['start_time']) + int(d['latency']), reverse=True)
        if read_processes:
            last_edge = read_processes[0]
            back_track_data[s_node] = {
                'read': [last_edge]
            }
    if write_processes:
        write_processes = list(filter(lambda d: (e_node == d['obj_pname']), write_processes))
        write_processes = sorted(write_processes, key=lambda d: int(d['start_time']) + int(d['latency']), reverse=True)
        if write_processes:
            last_write = write_processes[0]
            if last_edge:
                if (int(last_edge['start_time']) + int(last_edge['latency'])) < (int(last_write['start_time']) + int(last_write['latency'])):
                    last_edge = last_write
                    back_track_data[s_node] = {
                        'write': [last_edge]
                    }
            else:
                last_edge = last_write
                back_track_data[s_node] = {
                    'write': [last_edge]
                }
    timestamp = (int(last_edge['start_time']) + int(last_edge['latency'])) // pow(10, 9)
    backtrack(s_node, timestamp)


if __name__ == '__main__':
    import shutil
    shutil.rmtree("doctest-output")

    read()
    graph(log_data, file_name='complete_graph')

    s_node = "sh17885"
    e_node = "/home/sujatha/Documents/software-security/scripts/s5.sh"
    find_edge(s_node, e_node)
    graph(back_track_data, file_name='backtrack')
