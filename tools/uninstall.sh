# Change the directory
cd /home/alvin/third-parties/sofa
[[ $(pwd) != /home/alvin/third-parties/sofa ]] && echo "Fail to change directory. Stop uninstalling..." && exit 1
# Remove installed files
rm -f bin/sofa bin/sofa_record.py bin/sofa_preprocess.py bin/sofa_analyze.py bin/STree.py bin/sofa_viz.py bin/sofa_config.py bin/sofa_print.py bin/sofa_common.py bin/potato_pb2.py bin/potato_pb2_grpc.py sofa-pcm/pcm-core.x sofa-pcm/pcm-numa.x sofa-pcm/pcm-pcie.x sofa-pcm/pcm-memory.x
rm -f plugins/.placeholder
rm -f sofaboard/index.html sofaboard/context.txt sofaboard/cpu-report.html sofaboard/gpu-report.html sofaboard/comm-report.html sofaboard/overhead.html sofaboard/timeline.js sofaboard/potato_report.css
# Remove all python caches
rm -rf __pycache__ plugins/__pycache__ bin/__pycache__
# Remove generated files
rm -f tools/activate.sh
rm -f tools/uninstall.sh
# Remove directory only if it is empty!
rmdir --ignore-fail-on-non-empty bin sofaboard plugins tools
rmdir --ignore-fail-on-non-empty /home/alvin/third-parties/sofa
