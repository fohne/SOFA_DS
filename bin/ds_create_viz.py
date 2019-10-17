import os
def ds_create_viz(dds_logpath, nodes_record_dir):
    sofa_home = os.path.dirname(os.path.realpath(__file__))
    #os.system('cp %s/../sofaboard/ds_index_template ./' % sofa_home)
    #os.system('cp %s/../sofaboard/timeline.js ./' % sofa_home)
    
    f = open('%s/../sofaboard/ds_index_template' % sofa_home ,'r')
    index = f.read()
    f.close()
    loc = index.find('<!--BODY-->')
    loc = loc + len('<!--BODY-->')
    top_index = index[:loc]
    bottom_index = index[loc:]
    

    f = open('%s/../sofaboard/timeline.js' % sofa_home)
    timeline = f.read()
    f.close
    replace_string = ''
    for i in range(len(nodes_record_dir)):
        top_index = top_index + '\n        <div id="container%s" style="min-width: 310px; height: 400px; max-width: 90%%; margin: 0 auto"></div>' % nodes_record_dir[i]
        top_index = top_index + '\n        <script src="report%s.js"></script>' % nodes_record_dir[i]
        top_index = top_index + '\n        <script src="timeline%s.js"></script>\n' % nodes_record_dir[i]

        replace_string = timeline.replace('container', 'container%s' % nodes_record_dir[i])
        replace_string = replace_string.replace('sofa_traces', 'sofa_traces%s' % nodes_record_dir[i])
        replace_string = replace_string.replace('Time Versus Functions and Events', 'Functions and Events Timeline on Node %s' % nodes_record_dir[i])

        f = open('timeline%s.js' % nodes_record_dir[i], 'w')
        f.write(replace_string)
        os.system('cp %s/report.js ./report%s.js' % (nodes_record_dir[i], nodes_record_dir[i]))
        f.close()
        pass
    
    f = open('%s/../sofaboard/connect_timeline.js' % sofa_home)
    connection_view_timeline = f.read()
    f.close()
    f = open('connect_timeline.js', 'w')
    f.write(connection_view_timeline)
    f.close()  
    top_index = top_index + \
              '\n        <div id="container" style="min-width: 310px; height: 400px; max-width: 90%%; margin: 0 auto"></div>'
    top_index = top_index + '\n        <script src="connect_view_data.js"></script>'
    top_index = top_index + '\n        <script src="connect_timeline.js"></script>\n'

    index = top_index + bottom_index
    f = open('./index.html', 'w')
    f.write(index)
    f.close()

