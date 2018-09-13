all:
	for i in $(shell ls); do \
		[ -f $${i} ] && continue; \
		cd $${i}; go build -buildmode=plugin; \
		cd ..; \
	done
clean:
	for i in $(shell ls); do \
		[ -f $${i} ] && continue; \
		cd $${i}; rm -f $${i}.so; \
		cd ..; \
	done
