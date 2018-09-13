needmake = search
project = $(shell basename $(shell pwd))

all: need
	go build

need:
	for i in ${needmake}; do \
		make -C $${i}; \
	done

clean:
	rm -f ${project}
	for i in ${needmake}; do \
		make -C $${i} clean; \
	done
