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
    pre_index = index[:loc]
    post_index = index[loc:]
    

    f = open('%s/../sofaboard/timeline.js' % sofa_home)
    timeline = f.read()
    f.close
    replace_string = ''
    for i in range(len(nodes_record_dir)):
        pre_index = pre_index + '\n        <div id="container%s" style="min-width: 310px; height: 400px; max-width: 90%%; margin: 0 auto"></div>' % nodes_record_dir[i]
        pre_index = pre_index + '\n        <script src="report%s.js"></script>' % nodes_record_dir[i]
        pre_index = pre_index + '\n        <script src="timeline%s.js"></script>\n' % nodes_record_dir[i]

        replace_string = timeline.replace('container', 'container%s' % nodes_record_dir[i])
        replace_string = replace_string.replace('sofa_traces', 'sofa_traces%s' % nodes_record_dir[i])
        f = open('timeline%s.js' % nodes_record_dir[i], 'w')
        f.write(replace_string)
        os.system('cp %s/report.js ./report%s.js' % (nodes_record_dir[i], nodes_record_dir[i]))
        f.close()
        pass
        
    index = pre_index + post_index
    f = open('./index.html', 'w')
    f.write(index)
    f.close()

