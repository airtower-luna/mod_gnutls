TARGETS = $(foreach x,pdf html,mod_gnutls_manual.$(x))
all: $(TARGETS)

mod_gnutls_manual.%: mod_gnutls_manual.mdwn
	pandoc --toc -f markdown -o $@ $<

clean:
	rm -f $(TARGETS)

.PHONY: all clean
