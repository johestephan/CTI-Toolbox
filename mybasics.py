

def StoXML(selftype, value):
    return '''
<indicator>
<type> %s </type>
<value> %s </value>
</indicator>
''' % (selftype, value)

