 #!/bin/bash
 kubectl exec -it $(kubectl get pods -n kubeinvaders | grep -v NAME | awk '{ print $1 }') -n kubeinvaders -- /bin/bash
