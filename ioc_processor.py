import csv
import json
import urllib2
import datetime
import os
import re

def main():
    master_list = list()

    # Open the configuration file and pull sources
    with open('input.csv') as sources_file:
        sources = list(csv.reader(sources_file))
    
    # Process each source and add the results to the master list
    for item in sources:
        if len(item) == 3:
            master_list += pullFromSite(item[0],item[1],bool(item[2]))
        else:
            master_list += pullFromSite(item[0],item[1])

    # Process and add the manual list
    master_list += manualProcessor(30)

    # TODO sort through list for redundancy
    # TODO output to file

    if os.path.exists("result.csv"):
        os.remove("result.csv")

    master_list = sorted(master_list)
    #print master_list

    final_list = list()


    pattern = re.compile('([^\s\w]|_)+')

    for val, item in enumerate(master_list):
        if val >= len(master_list) - 1:
            final_list.append(item)
            #final_list.append([item[0],pattern.sub('', item[1])])
        else:
            nextItem = master_list[val+1]

            if item[0] is not nextItem[0]:
                final_list.append(item)
                #final_list.append([item[0],pattern.sub('', item[1])])

    # Write results to the results file
    with open('result.csv', 'wb') as csvfile:
        fieldnames = ['ip', 'tag']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for item in final_list:
            writer.writerow({'ip': item[0], 'tag': item[1]})


# Processes give site along with a source label or row address
def pullFromSite(site, source, isCSV = False):
    response = urllib2.urlopen(site)

    if isCSV:
        data = list(csv.reader(response))

    else:
        data = response.read()
        data = json.loads(data)

    result_ips = list()

    #Cymon use case
    if 'results' in data:
        size = len(data['results'])
        x = 0
        # pull out all of the addresses and store them in our list
        while x < size:
            result_ips.append([data['results'][x]['addr'],"Malicious Activity"])
            x += 1

    else:
        for row in data:
            # Checking for comment lines and ignoring them
            if not row[0].startswith("#"):
                if source.isdigit():
                    result_ips.append([row[0], row[int(source)]])
                else:
                    result_ips.append([row[0], source])

    return result_ips

# Processes manually entered addresses
def manualProcessor(falloffdays):

    # Setup list early so if stuff fails the list still exists
    result_ips = list()
    currentData = list()

    # opens up saved data if it exists
    if os.path.exists('./manual_data.csv'):
        with open('manual_data.csv') as sources_file:
            oldData = list(csv.reader(sources_file))
    
        current_time = (str(datetime.datetime.now().replace(microsecond=0))).replace(" ", "_")

        # backup the old data just in case and time stamp it
        with open('old/Old_Manual_list_' + current_time + '.csv', "w") as backup:
            filewriter = csv.writer(backup, delimiter=',',quotechar='|', quoting=csv.QUOTE_MINIMAL)
            for infoPiece in oldData:
                filewriter.writerow(infoPiece)

        # Trim out of date material
        for item in oldData:
            if (datetime.datetime.now() - datetime.datetime.strptime(item[2], '%Y-%m-%d')) < datetime.timedelta(days=falloffdays):
                currentData.append(item) 

        # sets asside the current data
        result_ips = currentData

    

    # Instantiate the new data list
    newManualData = list()
    files = list()

    # open new data if it exists in the folder
    if os.path.isdir("input_files"):
        files = os.listdir("input_files")

        # If files is false, that means the string is empty and therefor the input folder is empty
        if files:
            for file in files:
                # Stripping the .csv from the end of the file
                name = file.split(".")[0]

                # Open the next file and put it in a usable format
                with open('input_files/'+name+'.csv') as source_file:
                    moreData = list(csv.reader(source_file))

                    # For each file opened go through the file and add all the new data with the file name
                    for piece in moreData:
                        newManualData.append([piece[0],name])

    # Else create the input folder
    else:
        os.makedirs("input_files")  

    #Add the new data
    if newManualData:
        # Check each new item against the old list, if it is found break out of the loop
        # and start checking the next ip, if it is never found add it to the results list
        Found = False
        for newItem in newManualData:
            for item in currentData:
                if item[0] == newItem[0]:
                    Found = True
                    break
            if Found:
                Found = False
            else:
                result_ips.append([newItem[0],newItem[1], str(datetime.date.today())])

    # If there is no old data build up a new list and date the items
    else:
        # Check if their is new manual data even
        if newManualData:
            for item in newManualData:
                result_ips.append([item[0],item[1], str(datetime.date.today())])

    # Remove old file if it exists
    if os.path.exists('./manual_data.csv'):
        os.remove('manual_data.csv')

    if files:
        for file in files:
            print ("deleting " + file)
            try:
                os.remove('input_files/'+name+'.csv')
            except:
                print "derp"

    #write the new information grab
    if result_ips:
        with open('manual_data.csv', "w") as newVersion:
            filewriter = csv.writer(newVersion, delimiter=',',quotechar='|', quoting=csv.QUOTE_MINIMAL)
            for infoPiece in result_ips:
                filewriter.writerow(infoPiece)

    final_result = list()
    for item in result_ips:
    	print item[0]
    	print item[1]
        final_result.append([item[0],item[1]])

    return final_result

main()
