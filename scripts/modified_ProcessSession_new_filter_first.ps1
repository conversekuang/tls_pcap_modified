# Wei Wang (ww8137@mail.ustc.edu.cn)
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file, You
# can obtain one at http://mozilla.org/MPL/2.0/.
# 2_\Session_AllLayers
#  |__non-vpn
#        |__chat 
#             |__chat1-ALL 
#                     |___xxx.pcap
# ==============================================================================

$SESSIONS_COUNT_LIMIT_MIN = 0
$SESSIONS_COUNT_LIMIT_MAX = 6000
$TRIMED_FILE_LEN = 784

#$PATH = @(@())
#[System.Collections.ArrayList]$arraylist =$PATH



# 需要修改2处，可选：Session_AllLayers,  Session_L7,  Flow_AllLayers,  Flow_L7, 

$TYPE_DIR = "Session_AllLayers"
$SOURCE_SESSION_DIR = "2_\Modified_Session_AllLayers"


echo "If Sessions more than $SESSIONS_COUNT_LIMIT_MAX we only select the largest $SESSIONS_COUNT_LIMIT_MAX."
echo "Finally Selected Sessions:"

# 以下代码就是讲文件分为训练集和测试集并赋值到指定目录。

#$directories = gci $SOURCE_SESSION_DIR -Directory
# gci是定位到$SOURCE_SESSION_DIR目录下，-Directory返回的是文件夹
# vpn non-vpn

#foreach($directory in $directories)
#{   
#    
#    $dirs = gci $directory.Fullname
#    # chat voip...
#
#    foreach($dir in $dirs)
#    {
#        echo "$TYPE_DIR\$($directory.BaseName)\$($dir.BaseName)\Test"
#        $ds = gci $dir.Fullname
#        # chat1-ALL
#
#        #foreach($d in $ds)
#        #{
#        #    $files = gci $ds.FullName
#        #    # 返回的是绝对路径全名称
#        #    # .pcap文件   
#        #    $count = $files.count
#        #    # 文件数量
#        #    if($count -gt $SESSIONS_COUNT_LIMIT_MIN)
#        #    # 如果文件数量大于最小的
#        #    {             
#        #        echo "$($d.Name) $count"        
#        #        if($count -gt $SESSIONS_COUNT_LIMIT_MAX)
#        #        {   
#        #            # 如果文件数量大于最大的，按照文件大小从大到小排序，选择前面的$SESSIONS_COUNT_LIMIT_MAX个文件
#        #            $files = $files | sort Length -Descending | select -First $SESSIONS_COUNT_LIMIT_MAX
#        #            $count = $SESSIONS_COUNT_LIMIT_MAX
#        #        }
#        #        $files = $files | resolve-path
#        #        # 打印出绝对路径的文件
#        #        # Ignore the .pcap file that has less than 10 packets
#        #        $test  = $files | get-random -count ([int]($count/10))
#        #        # 将文件划分为10份，随机取其中一份的数量作为测试集                
#        #        $train = $files | ?{$_ -notin $test}    
#        #        # 将剩下的文件作为训练集
#        #        $path_test  = "3_\Filtered\$TYPE_DIR\$($directory.BaseName)\$($dir.BaseName)\Test\$($d.Name)"        
#        #        $path_train = "3_\Filtered\$TYPE_DIR\$($directory.BaseName)\$($dir.BaseName)\Train\$($d.Name)"
#        #        # 设置存储路径
#        #        
#        #        ni -Path $path_test -ItemType Directory -Force
#        #        ni -Path $path_train -ItemType Directory -Force    
#        #        # 创建存储路径，新项
#        #        
#        #        cp $test -destination $path_test        
#        #        cp $train -destination $path_train
#        #        # 将复制到指定目录
#        #    }
#        #}
#
#        
#        # 添加目录列表
#        #$arraylist.Add(("3_\Filtered\$TYPE_DIR\$($directory.BaseName)\$($dir.BaseName)\Test", "3_\Trimed\$TYPE_DIR\$($directory.BaseName)\$($dir.BaseName)\Test"))
#        #$arraylist.Add(("3_\Filtered\$TYPE_DIR\$($directory.BaseName)\$($dir.BaseName)\Train", "3_\Trimed\$TYPE_DIR\$($directory.BaseName)\$($dir.BaseName)\Train"))
#    }
#}

# 以下代码就是将文件编辑到784 = 28*28的大小

echo "All files will be trimed to $TRIMED_FILE_LEN length and if it's even shorter we'll fill the end with 0x00..."
$srcpaths = "2_\Modified_Session_AllLayers\non-vpn"
$dstpaths = "2_\Modified_Session_AllLayers\non-vpn_trim"
# 刚才上面分好的目录 用二维数组代替


$dirs = gci $srcpaths -Directory
foreach ($d in $dirs ) # 
{
    ni -Path "$($dstpaths)\$($d.Name)" -ItemType Directory -Force
    #根据FilteredSession新建TrimedSession文件夹
    foreach($f in gci $d.fullname)
    {   
      echo "$($f.Name)"
      # 读取FilteredSession文件夹的文件，按bytes读取
      $content = [System.IO.File]::ReadAllBytes($f.FullName)
      $len = $f.length - $TRIMED_FILE_LEN
      # 如果文件长度大于784，截取
      if($len -gt 0)
      {   
          $content = $content[0..($TRIMED_FILE_LEN-1)]        
      }
      # 如果文件长度小于784，填充0x00 bytes
      elseif($len -lt 0)
      {        
          $padding = [Byte[]] (,0x00 * ([math]::abs($len)))
          $content = $content += $padding
      }
      Set-Content -value $content -encoding byte -path "$($dstpaths)\$($d.Name)\$($f.Name)"
      # 将content写入到文件中
    }        
}
